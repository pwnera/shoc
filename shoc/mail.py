"""Email to the people who sign in: invitations, resets and locks (SEC-3, RFC 0028).

`smtplib` from the standard library, against the company's own mail server
(SHOC_SMTP_URL). Certificates are verified, and plain `smtp://` must upgrade
with STARTTLS or nothing is sent. Recipients and links come from stored rows
and SHOC_PUBLIC_URL, never from the request that caused the mail.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
import threading
from email.message import EmailMessage
from urllib.parse import unquote, urlsplit

from shoc.config import Config
from shoc.errors import ConfigError

log = logging.getLogger("shoc.mail")
TIMEOUT = 20


def _sender(cfg: Config) -> str:
    user = unquote(urlsplit(cfg.smtp_url).username or "")
    return cfg.mail_from or (user if "@" in user else "")


def configured(cfg: Config) -> bool:
    """A mail server, and an address to send from."""
    return bool(cfg.smtp_url and _sender(cfg))


def send(cfg: Config, to: str, subject: str, body: str) -> None:
    url = urlsplit(cfg.smtp_url)
    user, password = unquote(url.username or ""), unquote(url.password or "")
    sender = _sender(cfg)
    if not sender:
        raise ConfigError("set SHOC_MAIL_FROM: the SMTP user is not an address")
    message = EmailMessage()  # refuses a header value with a line break
    message["From"], message["To"], message["Subject"] = sender, to, subject
    message.set_content(body)
    context = ssl.create_default_context()
    if url.scheme == "smtps":
        client: smtplib.SMTP = smtplib.SMTP_SSL(
            url.hostname or "", url.port or 465, timeout=TIMEOUT, context=context
        )
    elif url.scheme == "smtp":
        client = smtplib.SMTP(url.hostname or "", url.port or 587, timeout=TIMEOUT)
    else:
        raise ConfigError("SHOC_SMTP_URL must start with smtps:// or smtp://")
    with client:
        if url.scheme == "smtp":
            client.ehlo()
            if not client.has_extn("starttls"):
                raise ConfigError(f"{url.hostname} offers no STARTTLS; nothing was sent")
            client.starttls(context=context)
            client.ehlo()
        if user:
            client.login(user, password)
        client.send_message(message)


def send_later(cfg: Config, to: str, subject: str, body: str) -> None:
    """Send from a thread of its own; a failure is logged, never raised into a request."""

    def run() -> None:
        try:
            send(cfg, to, subject, body)
        except Exception as exc:
            log.warning("could not email %s: %s", to, exc)

    threading.Thread(target=run, daemon=True, name="shoc-mail").start()


def link_url(cfg: Config, link: str) -> str:
    """Where a link opens: the console's /welcome, with the link in the fragment."""
    return f"{cfg.public_url}/welcome#{link}"


def invitation(cfg: Config, link: str, days: int) -> tuple[str, str]:
    return (
        "Your shoc account",
        f"You have a shoc account at {cfg.public_url}.\n\n"
        f"Open this link within {days} day(s) to set a password and an authenticator:\n"
        f"{link_url(cfg, link)}\n",
    )


def reset(cfg: Config, link: str, days: int) -> tuple[str, str]:
    return (
        "Reset your shoc sign-in",
        f"An admin reset your shoc sign-in at {cfg.public_url}.\n\n"
        f"Open this link within {days} day(s) to set a new password and authenticator:\n"
        f"{link_url(cfg, link)}\n\n"
        "If you did not ask for this, tell your admin.\n",
    )


def forgot(cfg: Config, link: str) -> tuple[str, str]:
    return (
        "Set a new shoc password",
        f"Someone asked to set a new password for your shoc account at {cfg.public_url}.\n\n"
        "Open this link within an hour. You will need a code from your authenticator:\n"
        f"{link_url(cfg, link)}\n\n"
        "If it was not you, ignore this email. Your password has not changed.\n",
    )


def locked(cfg: Config, minutes: int) -> tuple[str, str]:
    return (
        "Your shoc account is locked",
        f"Five wrong authenticator codes were entered for your shoc account at "
        f"{cfg.public_url}, after the right password. Sign-in is locked for {minutes} "
        "minutes.\n\nIf it was not you, someone has your password: set a new one with "
        '"Forgot password" and tell your admin.\n',
    )
