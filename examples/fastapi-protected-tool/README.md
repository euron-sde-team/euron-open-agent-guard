# FastAPI protected tool

A client-side `authorize` only helps if the agent calls it. This service does not trust the
agent: it acts only on a decision token AgentGuard issued for exactly this request body,
verifies it against AgentGuard's public keys, recomputes the action hash from the body, and
redeems it once. The protection is three lines in `service.py`: the verifier, and the
`Depends(require_decision(...))` parameter.

```bash
pip install "./sdks/python[fastapi]" uvicorn
eval "$(uv run --with httpx python examples/bootstrap.py)"
cd examples/fastapi-protected-tool
uvicorn service:app --port 8095 &
python agent.py http://localhost:8095
```

```text
no token        -> 401 {"detail":{"code":"missing_token",...}}
other amount    -> 403 {"detail":{"code":"params_mismatch",...}}
valid token     -> 200 {"refunded":45,"customer":"c-3001",...}
replayed token  -> 403 {"detail":{"code":"already_used",...}}
```

If the service reaches AgentGuard on another address than its public URL (inside Docker, for
example), pass `issuer=` with the API's `PUBLIC_API_URL` to the verifier.
