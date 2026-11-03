from __future__ import annotations

from fastapi import APIRouter, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import Field
from redis.exceptions import RedisError

from agentguard.audit.service import Actor, audit
from agentguard.auth import oidc, service
from agentguard.auth.dependencies import (
    SESSION_COOKIE,
    CurrentUser,
    OrgAdmin,
    current_user,
    revoke,
    session_token,
)
from agentguard.auth.schemas import (
    AcceptInvitation,
    InvitationPreview,
    LoginRequest,
    PasswordChange,
    SignInOut,
    SignupRequest,
    UserOut,
)
from agentguard.core.deps import ContainerDep, SessionDep, client_ip
from agentguard.core.errors import AuthenticationError, RateLimitedError
from agentguard.core.schemas import Ack, ApiModel
from agentguard.core.security import decode_session, issue_session
from agentguard.limits.limiter import LimitDecision
from agentguard.org.models import Org
from agentguard.users.models import User

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


async def _throttle(container: ContainerDep, key: str, rpm: int, message: str) -> None:
    try:
        decision = await container.kv.hit(key, rpm)
    except (RedisError, OSError):
        # Throttling is a convenience; lockout lives in Postgres and still applies.
        decision = LimitDecision(allowed=True)
    if not decision.allowed:
        raise RateLimitedError(message, headers={"retry-after": str(decision.retry_after_s)})


async def _session(
    response: Response, container: ContainerDep, session: SessionDep, user: User
) -> SignInOut:
    settings = container.settings
    token = issue_session(
        user.id,
        user.role,
        user.session_version,
        settings.session_secret,
        settings.session_ttl_hours,
    )
    ttl = settings.session_ttl_hours * 3600
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=ttl,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )
    response.headers["cache-control"] = "no-store"
    org = await session.get(Org, user.org_id)
    return SignInOut(
        user=UserOut.model_validate(user),
        org_slug=org.slug if org else "",
        session_token=token,
        expires_in_s=ttl,
    )


@router.post("/login", response_model=SignInOut, summary="Sign in to the dashboard")
async def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    container: ContainerDep,
    session: SessionDep,
) -> SignInOut:
    ip = client_ip(request)
    await _throttle(
        container,
        f"login:{ip}",
        container.settings.login_rpm,
        "Too many sign-in attempts from this address. Wait a minute and try again",
    )
    user = await service.authenticate(session, container.settings, body.email, body.password, ip)
    return await _session(response, container, session, user)


@router.post(
    "/signup",
    response_model=SignInOut,
    status_code=201,
    summary="Create an organisation and its administrator account",
)
async def signup(
    body: SignupRequest,
    request: Request,
    response: Response,
    container: ContainerDep,
    session: SessionDep,
) -> SignInOut:
    ip = client_ip(request)
    await _throttle(
        container,
        f"signup:{ip}",
        container.settings.signup_rpm,
        "Too many sign-ups from this address. Wait a minute",
    )
    user, _ = await service.signup(
        session, container.settings, body.org_name, body.name, body.email, body.password, ip
    )
    return await _session(response, container, session, user)


class SignupStatus(ApiModel):
    signup_enabled: bool


@router.get("/signup", response_model=SignupStatus, summary="Whether new organisations may sign up")
async def signup_status(container: ContainerDep) -> SignupStatus:
    return SignupStatus(signup_enabled=container.settings.signup_enabled)


@router.get(
    "/invitations/{token}", response_model=InvitationPreview, summary="Who an invitation is for"
)
async def preview_invitation(
    token: str, container: ContainerDep, session: SessionDep
) -> InvitationPreview:
    invitation = await service.find_invitation(session, container.settings, token)
    org = await session.get(Org, invitation.org_id)
    return InvitationPreview(
        email=invitation.email, role=invitation.role, org_name=org.name if org else ""
    )


@router.post(
    "/invitations/accept", response_model=SignInOut, status_code=201, summary="Accept an invitation"
)
async def accept_invitation(
    body: AcceptInvitation,
    request: Request,
    response: Response,
    container: ContainerDep,
    session: SessionDep,
) -> SignInOut:
    ip = client_ip(request)
    await _throttle(
        container, f"accept:{ip}", container.settings.signup_rpm, "Too many attempts. Wait a minute"
    )
    user = await service.accept(
        session, container.settings, body.token, body.name, body.password, ip
    )
    return await _session(response, container, session, user)


@router.post("/logout", response_model=Ack, summary="Sign out")
async def logout(
    request: Request, response: Response, container: ContainerDep, session: SessionDep
) -> Ack:
    """Ends this session server-side too: the token is refused until it expires."""
    token, _ = session_token(request)
    claims = decode_session(token, container.settings.session_secret) if token else None
    if claims is not None:
        await revoke(session, claims)
        user = await session.get(User, claims.user_id)
        if user is not None:
            audit(
                session,
                Actor(user.org_id, user.id, user.email, user.role, client_ip(request)),
                "auth.logout",
                "user",
                user.id,
            )
        await session.commit()
    response.delete_cookie(SESSION_COOKIE, path="/")
    return Ack(message="Signed out")


class SessionOut(ApiModel):
    user: UserOut | None
    org_slug: str | None = None
    org_name: str | None = None


@router.get("/session", response_model=SessionOut, summary="Who is signed in, if anyone")
async def current_session(
    request: Request, container: ContainerDep, session: SessionDep
) -> SessionOut:
    if not session_token(request)[0]:
        return SessionOut(user=None)
    try:
        user = await current_user(request, container, session)
    except AuthenticationError:
        return SessionOut(user=None)
    org = await session.get(Org, user.org_id)
    return SessionOut(
        user=UserOut.model_validate(user),
        org_slug=org.slug if org else None,
        org_name=org.name if org else None,
    )


@router.get("/me", response_model=UserOut, summary="The signed-in user")
async def me(user: CurrentUser) -> User:
    return user


@router.post("/password", response_model=SignInOut, summary="Change your password")
async def password(
    body: PasswordChange,
    request: Request,
    response: Response,
    user: CurrentUser,
    container: ContainerDep,
    session: SessionDep,
) -> SignInOut:
    actor: Actor = request.state.actor
    user = await service.change_password(
        session, user, body.current_password, body.new_password, actor
    )
    return await _session(response, container, session, user)


class OidcIn(ApiModel):
    issuer: str = Field(..., max_length=500)
    client_id: str = Field(..., min_length=1, max_length=255)
    # Write-only; omit to keep the stored one.
    client_secret: str | None = Field(None, max_length=1000)
    allowed_domains: list[str] = Field(default_factory=list, max_length=50)
    role_claim: str = Field("groups", max_length=64)
    role_map: dict[str, str] = Field(default_factory=dict)
    default_role: str = ""
    enabled: bool = True


class OidcOut(ApiModel):
    configured: bool
    issuer: str | None = None
    client_id: str | None = None
    allowed_domains: list[str] = Field(default_factory=list)
    role_claim: str = "groups"
    role_map: dict[str, str] = Field(default_factory=dict)
    default_role: str = ""
    enabled: bool = False
    redirect_uri: str


@router.get("/oidc", response_model=OidcOut, summary="Single sign-on settings")
async def get_oidc(actor: OrgAdmin, container: ContainerDep, session: SessionDep) -> OidcOut:
    from sqlalchemy import select

    from agentguard.auth.models import OidcProvider

    row = await session.scalar(select(OidcProvider).where(OidcProvider.org_id == actor.org_id))
    if row is None:
        return OidcOut(configured=False, redirect_uri=oidc.redirect_uri(container))
    return OidcOut(
        configured=True,
        issuer=row.issuer,
        client_id=row.client_id,
        allowed_domains=row.allowed_domains,
        role_claim=row.role_claim,
        role_map=row.role_map,
        default_role=row.default_role,
        enabled=row.enabled,
        redirect_uri=oidc.redirect_uri(container),
    )


@router.put("/oidc", response_model=OidcOut, summary="Set up single sign-on (OpenID Connect)")
async def put_oidc(
    body: OidcIn, actor: OrgAdmin, container: ContainerDep, session: SessionDep
) -> OidcOut:
    await oidc.save_provider(container, session, actor, **body.model_dump())
    return await get_oidc(actor, container, session)


@router.get(
    "/oidc/{org_slug}/start", summary="Start single sign-on (redirects to the identity provider)"
)
async def oidc_start(
    org_slug: str, container: ContainerDep, session: SessionDep
) -> RedirectResponse:
    url, cookie = await oidc.start(container, session, org_slug)
    response = RedirectResponse(url, status_code=302)
    response.set_cookie(
        oidc.STATE_COOKIE,
        cookie,
        max_age=oidc.STATE_TTL_S,
        httponly=True,
        samesite="lax",
        secure=container.settings.cookie_secure,
        path="/api/v1/auth/oidc",
    )
    return response


@router.get("/oidc/callback", summary="Single sign-on callback from the identity provider")
async def oidc_callback(
    code: str, state: str, request: Request, container: ContainerDep, session: SessionDep
) -> RedirectResponse:
    try:
        user = await oidc.callback(
            container,
            session,
            code=code,
            state=state,
            cookie=request.cookies.get(oidc.STATE_COOKIE),
            ip=client_ip(request),
        )
    except AuthenticationError as exc:
        from urllib.parse import quote

        return RedirectResponse(
            f"{container.settings.public_url}/login?error={quote(exc.message)}", status_code=302
        )
    response = RedirectResponse(f"{container.settings.public_url}/overview", status_code=302)
    await _session(response, container, session, user)
    response.delete_cookie(oidc.STATE_COOKIE, path="/api/v1/auth/oidc")
    return response
