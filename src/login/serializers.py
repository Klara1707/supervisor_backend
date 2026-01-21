# src/login/serializers.py
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import UserTrainingProgress

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "first_name", "last_name", "site"]


class UserTrainingProgressSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTrainingProgress
        fields = ["progress_by_popup"]


# Registration serializer for RegisterView
class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ["username", "password", "first_name", "last_name", "site"]

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data["username"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            site=validated_data.get("site", None),
        )
        return user
