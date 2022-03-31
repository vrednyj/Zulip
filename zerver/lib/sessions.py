import logging
import time
from datetime import timedelta
from importlib import import_module
from typing import Any, List, Mapping, Optional, Type, cast

from django.conf import settings
from django.contrib.auth import SESSION_KEY, get_user_model
from django.contrib.sessions.backends.base import SessionBase, UpdateError
from django.contrib.sessions.exceptions import SessionInterrupted
from django.contrib.sessions.models import Session
from django.utils.cache import patch_vary_headers
from django.utils.http import http_date
from django.utils.timezone import now as timezone_now
from typing_extensions import Protocol

from zerver.lib.timestamp import datetime_to_timestamp, timestamp_to_datetime
from zerver.models import Realm, UserProfile, get_user_profile_by_id

logger = logging.getLogger(__name__)


class SessionEngine(Protocol):
    SessionStore: Type[SessionBase]


session_engine = cast(SessionEngine, import_module(settings.SESSION_ENGINE))


def get_session_dict_user(session_dict: Mapping[str, int]) -> Optional[int]:
    # Compare django.contrib.auth._get_user_session_key
    try:
        return get_user_model()._meta.pk.to_python(session_dict[SESSION_KEY])
    except KeyError:
        return None


def get_session_user(session: Session) -> Optional[int]:
    return get_session_dict_user(session.get_decoded())


def user_sessions(user_profile: UserProfile) -> List[Session]:
    return [s for s in Session.objects.all() if get_session_user(s) == user_profile.id]


def delete_session(session: Session) -> None:
    logger.debug("Deleting session-id %s", session.session_key)
    session_engine.SessionStore(session.session_key).delete()


def delete_user_sessions(user_profile: UserProfile) -> None:
    for session in Session.objects.all():
        if get_session_user(session) == user_profile.id:
            delete_session(session)


def delete_realm_user_sessions(realm: Realm) -> None:
    realm_user_ids = [user_profile.id for user_profile in UserProfile.objects.filter(realm=realm)]
    for session in Session.objects.filter(expire_date__gte=timezone_now()):
        if get_session_user(session) in realm_user_ids:
            delete_session(session)


def delete_all_user_sessions() -> None:
    for session in Session.objects.all():
        delete_session(session)


def delete_all_deactivated_user_sessions() -> None:
    for session in Session.objects.all():
        user_profile_id = get_session_user(session)
        if user_profile_id is None:  # nocoverage  # TODO: Investigate why we lost coverage on this
            continue
        user_profile = get_user_profile_by_id(user_profile_id)
        if not user_profile.is_active or user_profile.realm.deactivated:
            logger.info("Deactivating session for deactivated user %s", user_profile.id)
            delete_session(session)


def set_expirable_session_var(
    session: SessionBase, var_name: str, var_value: Any, expiry_seconds: int
) -> None:
    expire_at = datetime_to_timestamp(timezone_now() + timedelta(seconds=expiry_seconds))
    session[var_name] = {"value": var_value, "expire_at": expire_at}


def get_expirable_session_var(
    session: SessionBase, var_name: str, default_value: Any = None, delete: bool = False
) -> Any:
    if var_name not in session:
        return default_value

    try:
        value, expire_at = (session[var_name]["value"], session[var_name]["expire_at"])
    except (KeyError, TypeError):
        logging.warning("get_expirable_session_var: error getting %s", var_name, exc_info=True)
        return default_value

    if timestamp_to_datetime(expire_at) < timezone_now():
        del session[var_name]
        return default_value

    if delete:
        del session[var_name]
    return value


class LoggingSessionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session_key = request.COOKIES.get(settings.SESSION_COOKIE_NAME)
        request.session = session_engine.SessionStore(session_key)
        logger.debug(
            "Session key %s, loaded session %r", session_key, request.session.get(SESSION_KEY)
        )

        response = self.get_response(request)

        try:
            accessed = request.session.accessed
            modified = request.session.modified
            empty = request.session.is_empty()
        except AttributeError as e:
            logger.debug("Session metadata not found in session key %s: %s", session_key, e)
            return response
        # First check if we need to delete this cookie.
        # The session should be deleted only if the session is entirely empty.
        if settings.SESSION_COOKIE_NAME in request.COOKIES and empty:
            logger.debug("Clearing empty cookie for session key %s", session_key)
            response.delete_cookie(
                settings.SESSION_COOKIE_NAME,
                path=settings.SESSION_COOKIE_PATH,
                domain=settings.SESSION_COOKIE_DOMAIN,
                samesite=settings.SESSION_COOKIE_SAMESITE,
            )
            patch_vary_headers(response, ("Cookie",))
        else:
            if accessed:
                patch_vary_headers(response, ("Cookie",))
            if (modified or settings.SESSION_SAVE_EVERY_REQUEST) and not empty:
                logger.debug("Session key %s modified", session_key)
                if request.session.get_expire_at_browser_close():
                    max_age = None
                    expires = None
                else:
                    max_age = request.session.get_expiry_age()
                    expires_time = time.time() + max_age
                    expires = http_date(expires_time)
                # Save the session data and refresh the client cookie.
                # Skip session save for 500 responses, refs #3881.
                if response.status_code != 500:
                    try:
                        request.session.save()
                        logger.debug(
                            "Saved session key %s, user %s",
                            session_key,
                            request.session.get(SESSION_KEY),
                        )
                    except UpdateError as e:
                        logger.debug("Failed to save session key %s: %s", session_key, e)
                        raise SessionInterrupted(
                            "The request's session was deleted before the "
                            "request completed. The user may have logged "
                            "out in a concurrent request, for example."
                        )
                    logger.debug("Sending session cookie %s", session_key)
                    response.set_cookie(
                        settings.SESSION_COOKIE_NAME,
                        request.session.session_key,
                        max_age=max_age,
                        expires=expires,
                        domain=settings.SESSION_COOKIE_DOMAIN,
                        path=settings.SESSION_COOKIE_PATH,
                        secure=settings.SESSION_COOKIE_SECURE or None,
                        httponly=settings.SESSION_COOKIE_HTTPONLY or None,
                        samesite=settings.SESSION_COOKIE_SAMESITE,
                    )
        return response
