# ---- Password Reset API ----
from django.contrib.auth.forms import PasswordResetForm

# send_mail import removed (unused)
from django.conf import settings

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import get_user_model

from rest_framework import viewsets, permissions, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import UserSerializer
# ---- Admin JWT Login: only superusers ----
# ...existing code...

# ---- User Training Progress API ----
from .models import UserTrainingProgress


class PasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        # Accept either 'email' or 'username' (which is always the email address)
        email = request.data.get("email") or request.data.get("username")
        if not email:
            return Response(
                {"detail": "Email or username is required."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        email = email.strip().lower()
        User = get_user_model()
        user_exists = User.objects.filter(username__iexact=email).exists()
        form = PasswordResetForm({"email": email})
        # Monkey-patch form to use username as email
        form.get_users = lambda email: User.objects.filter(
            username__iexact=email, is_active=True
        )
        if not user_exists:
            return Response(
                {"detail": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )
        # Monkey-patch form to use username as the email field for sending
        orig_save = form.save

        def custom_save(*args, **kwargs):
            # Patch: set user.email to user.username for email sending
            for user in form.get_users(email):
                user.email = user.username
            return orig_save(*args, **kwargs)

        form.save = custom_save
        if form.is_valid():
            form.save(
                request=request,
                use_https=request.is_secure(),
                email_template_name="registration/password_reset_email.html",
                subject_template_name="registration/password_reset_subject.txt",
                from_email=getattr(settings, "DEFAULT_FROM_EMAIL", None),
            )
            return Response(
                {"detail": "Password reset email sent."},
                status=status.HTTP_200_OK,
            )
        return Response(
            {"detail": "Invalid email address or username."},
            status=status.HTTP_400_BAD_REQUEST,
        )


class TrainingProgressView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            progress = UserTrainingProgress.objects.get(user=request.user)
            # Flatten progress_by_popup to not use site
            flat_progress = progress.progress_by_popup or {}
            # If old data exists with site keys, flatten it
            if any(isinstance(v, dict) for v in flat_progress.values()):
                new_progress = {}
                for site_data in flat_progress.values():
                    if isinstance(site_data, dict):
                        for popup_id, checked in site_data.items():
                            new_progress[popup_id] = checked
                flat_progress = new_progress
                progress.progress_by_popup = flat_progress
                progress.save()
            return Response({"progress_by_popup": flat_progress})
        except UserTrainingProgress.DoesNotExist:
            return Response(
                {"detail": "No progress found for user."},
                status=status.HTTP_404_NOT_FOUND,
            )

    def post(self, request):
        popup_id = request.data.get("popup_id")
        checked_items = request.data.get("checked_items", [])
        if not popup_id:
            return Response(
                {"detail": "popup_id is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        progress, created = UserTrainingProgress.objects.get_or_create(
            user=request.user
        )
        progress_data = progress.progress_by_popup or {}
        progress_data[popup_id] = checked_items
        progress.progress_by_popup = progress_data
        progress.save()
        return Response({"progress_by_popup": progress_data})


User = get_user_model()


# ---- Users CRUD (protected) ----
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "username"


# ---- JWT Login: include user info in response ----
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    site = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        import logging

        logger = logging.getLogger("login")
        username = attrs.get("username")
        password = attrs.get("password")
        site = attrs.get("site")
        # Log the raw request body for debugging
        try:
            raw_body = self.context["request"].body
            logger.info(f"[DEBUG] Raw request body: {raw_body}")
        except Exception as e:
            logger.warning(f"[DEBUG] Could not log raw request body: {e}")
        logger.info(f"[DEBUG] attrs received in validate: {attrs}")
        logger.info(f"[DEBUG] Raw site value from request: {site}")
        if site:
            site = site.lower()
        logger.info(f"Login attempt for user: {username}, site: {site}")
        if not username or not password:
            logger.warning("Username and password are required.")
            raise serializers.ValidationError("Username and password are required.")
        try:
            user = User.objects.get(username__iexact=username)
        except User.DoesNotExist:
            logger.warning(f"No user found with username: {username}")
            raise serializers.ValidationError("No user found with this username.")
        if not user.check_password(password):
            logger.warning(f"Incorrect credentials for user: {username}")
            raise serializers.ValidationError("Incorrect credentials.")
        # Save the selected site if provided
        logger.info(
            f"[DEBUG] User object before update: username={user.username}, site={user.site}"
        )
        if site:
            logger.info(f"Updating user {username} site to: {site}")
            user.site = site
            user.save(update_fields=["site"])
            logger.info(
                f"[DEBUG] User object after update: username={user.username}, site={user.site}"
            )
        else:
            logger.info(f"No site provided for user {username}, not updating site.")
        self.user = user
        data = super().validate(attrs)
        data["user"] = {
            "id": self.user.id,
            "username": self.user.username,
            "first_name": self.user.first_name or "",
            "is_staff": self.user.is_staff,
            "is_superuser": self.user.is_superuser,
            "site": self.user.site,
        }
        logger.info(
            f"Login successful for user: {username}, current site: {self.user.site}"
        )
        return data


class UsersBySiteView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Only include normal users (not admin/superuser)
        users = User.objects.filter(is_superuser=False, is_staff=False)
        result = {}
        for user in users:
            site = user.site or "Unassigned"
            if site not in result:
                result[site] = []
            full_name = f"{user.first_name} {user.last_name}".strip()
            result[site].append(
                {
                    "id": user.id,
                    "username": user.username,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "full_name": full_name,
                }
            )
        return Response(result)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


class DeleteUserView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request):
        username = request.data.get("username")
        if not username:
            return Response(
                {"detail": "username is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        username = username.strip().lower()
        try:
            user = User.objects.get(username__iexact=username)
            user.delete()
            return Response(status=status.HTTP_204_NO_CONTENT)
        except User.DoesNotExist:
            return Response(
                {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
            )


# ---- Update Site API ----
class UpdateSiteView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        site = request.data.get("site")
        if not site:
            return Response(
                {"detail": "site is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        user = request.user
        user.site = site
        user.save(update_fields=["site"])
        return Response(
            {"detail": f"Site updated to {site}", "site": user.site},
            status=status.HTTP_200_OK,
        )


# ---- Admin JWT Login: only superusers ----
class AdminTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        data = super().validate(attrs)
        if not self.user.is_superuser:
            raise serializers.ValidationError(
                "Login only allowed for admin (superuser) accounts."
            )
        data["user"] = {
            "id": self.user.id,
            "username": self.user.username,
            "first_name": self.user.first_name,
            "last_name": self.user.last_name,
            "is_staff": self.user.is_staff,
            "is_superuser": self.user.is_superuser,
        }
        return data


class AdminTokenObtainPairView(TokenObtainPairView):
    serializer_class = AdminTokenObtainPairSerializer


# ---- Registration ----
class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=100)
    first_name = serializers.CharField(max_length=50)
    last_name = serializers.CharField(max_length=50)
    password = serializers.CharField(write_only=True)
    site = serializers.CharField(max_length=100, required=False, allow_blank=True)

    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already registered.")
        # Allow any email as username; optionally, validate as email format
        return value

    def validate_password(self, value):
        # Allow any password (no digit-only or length restriction)
        return value

    def create(self, validated_data):
        site = validated_data.get("site", None)
        return User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"],
            first_name=validated_data["first_name"],
            last_name=validated_data["last_name"],
            site=site,
        )


# ---- Registration View ----
class RegisterView(APIView):
    authentication_classes = []  # Allow unauthenticated registration
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        user = serializer.save()
        return Response(
            {
                "id": user.id,
                "username": user.username,
                "first_name": user.first_name,
                "last_name": user.last_name,
                "site": user.site,
            },
            status=status.HTTP_201_CREATED,
        )


# ---- Current user profile ----
@api_view(["GET"])
@permission_classes([IsAuthenticated])
def me_view(request):
    user = request.user
    return Response({"id": user.id, "username": user.username, "email": user.email})
