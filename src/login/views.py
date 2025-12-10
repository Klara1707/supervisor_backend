from django.contrib.auth import get_user_model

from rest_framework import viewsets, permissions, serializers, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import UserSerializer, UserTrainingProgressSerializer
# ---- Admin JWT Login: only superusers ----
# ...existing code...

# ---- User Training Progress API ----
from .models import UserTrainingProgress


class TrainingProgressView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            progress = UserTrainingProgress.objects.get(user=request.user)
            serializer = UserTrainingProgressSerializer(progress)
            return Response(serializer.data)
        except UserTrainingProgress.DoesNotExist:
            return Response(
                {"detail": "No progress found for user."},
                status=status.HTTP_404_NOT_FOUND,
            )

    def post(self, request):
        popup_id = request.data.get("popup_id")
        checked_items = request.data.get("checked_items", [])
        site = request.data.get("site")
        if not popup_id:
            return Response(
                {"detail": "popup_id is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        if not site:
            return Response(
                {"detail": "site is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        progress, created = UserTrainingProgress.objects.get_or_create(
            user=request.user
        )
        progress_data = progress.progress_by_popup or {}
        # Store progress under site and popup_id
        if site not in progress_data:
            progress_data[site] = {}
        progress_data[site][popup_id] = checked_items
        progress.progress_by_popup = progress_data
        progress.save()
        serializer = UserTrainingProgressSerializer(progress)
        return Response(serializer.data)


User = get_user_model()


# ---- Users CRUD (protected) ----
class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = "username"


# ---- JWT Login: include user info in response ----
class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")
        site = attrs.get("site")
        if not username or not password:
            raise serializers.ValidationError("Username and password are required.")
        if not username.lower().endswith("@riotinto.com"):
            raise serializers.ValidationError("Username must end with @riotinto.com")
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise serializers.ValidationError("No user found with this username.")
        if not user.check_password(password):
            raise serializers.ValidationError("Incorrect credentials.")
        # Save the selected site if provided
        if site:
            user.site = site
            user.save(update_fields=["site"])
            print(f"DEBUG: Saved site for user {user.username}: {user.site}")
        print(f"DEBUG: Logging in user {user.username}, first_name: {user.first_name}")
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
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name,
                    "full_name": full_name,
                }
            )
        return Response(result)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        print(
            "Login request data:", request.data
        )  # This prints to your backend terminal
        return super().post(request, *args, **kwargs)


class DeleteUserView(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request):
        username = request.data.get("username")
        if not username:
            return Response(
                {"detail": "username is required."}, status=status.HTTP_400_BAD_REQUEST
            )
        try:
            user = User.objects.get(username=username)
            user.delete()
            return Response(
                {"detail": f"User '{username}' deleted."}, status=status.HTTP_200_OK
            )
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
            "email": self.user.email,
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
        if not value.lower().endswith("@riotinto.com"):
            raise serializers.ValidationError("Username must end with @riotinto.com")
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
        print("Received registration data:", request.data)  # Debug log
        serializer = RegisterSerializer(data=request.data)
        if not serializer.is_valid():
            print("Serializer errors:", serializer.errors)  # Print validation errors
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
