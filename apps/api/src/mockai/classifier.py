"""A deterministic stand-in for the AI-assisted injection classifier.

Speaks the three wire formats AgentGuard uses (OpenAI ``/v1/chat/completions``, Anthropic
``/v1/messages``, Ollama ``/api/chat``) and answers the classifier prompt with JSON. It
flags content containing phrases a careful model would flag, including some the rule-based
detector deliberately does not know (so tests can show the classifier raising a verdict).
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import orjson
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter()
STATE: dict[str, Any] = {"mode": "normal", "requests": 0}
_FLAG = re.compile(
    r"ignore (?:all |the )?(?:previous|prior)|disregard|new instructions|you are now|"
    r"exfiltrate|send .* to http|without telling|do as i say|kindly forward all",
    re.I,
)


def _content(messages: list[dict[str, Any]]) -> str:
    return "\n".join(str(m.get("content", "")) for m in messages if m.get("role") == "user")


def verdict(text: str) -> dict[str, Any]:
    hit = _FLAG.search(text)
    if hit:
        return {
            "injection": True,
            "confidence": 0.93,
            "reason": f"asks the agent to {hit.group(0).lower()}",
        }
    return {"injection": False, "confidence": 0.08, "reason": "reads as ordinary content"}


async def _answer(messages: list[dict[str, Any]]) -> str | None:
    STATE["requests"] += 1
    if STATE["mode"] == "fail":
        return None
    if STATE["mode"] == "slow":
        await asyncio.sleep(30)
    if STATE["mode"] == "garbage":
        return "I think it is probably fine?"
    return orjson.dumps(verdict(_content(messages))).decode()


@router.post("/v1/chat/completions")
async def openai(request: Request) -> JSONResponse:
    body = await request.json()
    text = await _answer(body.get("messages", []))
    if text is None:
        return JSONResponse({"error": {"message": "mock failure"}}, status_code=503)
    return JSONResponse(
        {
            "id": "mock",
            "object": "chat.completion",
            "model": body.get("model", "mock"),
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
        }
    )


@router.post("/v1/messages")
async def anthropic(request: Request) -> JSONResponse:
    body = await request.json()
    text = await _answer(body.get("messages", []))
    if text is None:
        return JSONResponse({"error": {"message": "mock failure"}}, status_code=529)
    return JSONResponse(
        {
            "id": "mock",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
        }
    )


@router.post("/api/chat")
async def ollama(request: Request) -> JSONResponse:
    body = await request.json()
    text = await _answer(body.get("messages", []))
    if text is None:
        return JSONResponse({"error": "mock failure"}, status_code=503)
    return JSONResponse(
        {
            "model": body.get("model", "mock"),
            "message": {"role": "assistant", "content": text},
            "done": True,
        }
    )
