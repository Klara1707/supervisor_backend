from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
import logging


class LoggingJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        try:
            return super().authenticate(request)
        except AuthenticationFailed as exc:
            logger = logging.getLogger("login")
            logger.error(
                f"JWT authentication failed: {exc} (auth header: {request.headers.get('Authorization')})"
            )
            raise
