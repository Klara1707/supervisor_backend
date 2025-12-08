# src/login/serializers.py
from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email"]


# Serializer for UserTrainingProgress
from .models import UserTrainingProgress


class UserTrainingProgressSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserTrainingProgress
        fields = ["progress_by_popup"]
