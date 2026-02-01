import logging
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed

logger = logging.getLogger("login")
logger.info("[DEBUG] LoggingJWTAuthentication imported and ready.")


class LoggingJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        logger.info(
            f"[DEBUG] LoggingJWTAuthentication.authenticate called. Headers: {dict(request.headers)}"
        )
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            logger.warning("[DEBUG] No Authorization header present on request.")
        else:
            logger.info(
                f"[DEBUG] Authorization header present: {auth_header[:20]}... (truncated)"
            )
        try:
            result = super().authenticate(request)
            logger.info(f"[DEBUG] Authentication result: {result}")
            return result
        except AuthenticationFailed as exc:
            logger.error(
                f"JWT authentication failed: {exc} (auth header: {auth_header})"
            )
            raise
