"""Outgoing mail (ticket replies, invitations, portal links), one backend chosen by
``MAIL_BACKEND``.

* ``log``: nothing leaves the process. A line without the body is logged (bodies carry
  one-time links and customer data) and the message is kept in a small in-memory outbox,
  which development and the tests read.
* ``smtp``: plain SMTP (Mailpit locally on ``SMTP_HOST``:``SMTP_PORT``, any relay in
  production), through the standard library in a worker thread.
* ``ses``: Amazon SES through boto3, in a worker thread.

Every backend is called the same way, so the domains that send mail never branch on it.
"""

from __future__ import annotations

import asyncio
import logging
import smtplib
from collections import deque
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import parseaddr

from agentguard.core.aws import aws_client
from agentguard.core.config import Settings

log = logging.getLogger("agentguard.mail")

OUTBOX_SIZE = 200


@dataclass(frozen=True)
class Mail:
    to: str
    subject: str
    text: str
    html: str | None = None
    # Threading and routing headers: Message-ID, In-Reply-To, References, Reply-To.
    headers: tuple[tuple[str, str], ...] = ()
    from_name: str | None = None


# The ``log`` backend's outbox: newest last, bounded.
OUTBOX: deque[Mail] = deque(maxlen=OUTBOX_SIZE)


class MailError(Exception):
    """The message could not be handed to the mail backend."""


def _message(settings: Settings, mail: Mail) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = (
        f"{mail.from_name} <{settings.mail_from_address}>" if mail.from_name else settings.mail_from
    )
    msg["To"] = mail.to
    msg["Subject"] = mail.subject
    for name, value in mail.headers:
        msg[name] = value
    msg.set_content(mail.text)
    if mail.html:
        msg.add_alternative(mail.html, subtype="html")
    return msg


def _smtp(settings: Settings, mail: Mail) -> None:
    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as smtp:
        smtp.send_message(_message(settings, mail))


def _ses(settings: Settings, mail: Mail) -> None:
    # Raw send keeps the threading headers (send_email would drop them).
    aws_client(settings, "ses").send_raw_email(
        Source=settings.mail_from_address,
        Destinations=[mail.to],
        RawMessage={"Data": _message(settings, mail).as_bytes()},
    )


async def send(
    settings: Settings,
    to: str,
    subject: str,
    text: str,
    html: str | None = None,
    *,
    headers: dict[str, str] | None = None,
    from_name: str | None = None,
) -> None:
    """Hand one message to the configured backend; raises ``MailError`` when it refuses."""
    mail = Mail(
        to=to,
        subject=subject,
        text=text,
        html=html,
        headers=tuple((headers or {}).items()),
        from_name=from_name,
    )
    if settings.mail_backend == "log":
        OUTBOX.append(mail)
        _, address = parseaddr(to)
        domain = address.rsplit("@", 1)[-1] if "@" in address else "?"
        log.info("mail (log backend)", extra={"to_domain": domain, "subject": subject})
        return
    try:
        if settings.mail_backend == "smtp":
            await asyncio.to_thread(_smtp, settings, mail)
        else:
            await asyncio.to_thread(_ses, settings, mail)
    except Exception as exc:  # smtplib and botocore raise many unrelated types
        log.warning(
            "mail send failed",
            extra={"backend": settings.mail_backend, "error": type(exc).__name__},
        )
        raise MailError(f"the {settings.mail_backend} mail backend refused the message") from exc
