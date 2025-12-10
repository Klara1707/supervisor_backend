from django.contrib.auth.models import (
    AbstractBaseUser,
    PermissionsMixin,
    BaseUserManager,
)
from django.db import models


class UserTrainingProgress(models.Model):
    user = models.OneToOneField("User", on_delete=models.CASCADE)
    progress_by_popup = models.JSONField(
        default=dict
    )  # e.g. {"contractor1": [...], "contractor2": [...]}

    def __str__(self):
        return f"{self.user.username} training progress"


class UserManager(BaseUserManager):
    def create_user(self, username, password=None, **extra_fields):
        if not username:
            raise ValueError("Username is required")
        if not username.lower().endswith("@riotinto.com"):
            raise ValueError("Username must end with @riotinto.com")
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, username, password=None, **extra_fields):
        if password is None:
            raise ValueError("Superusers must have a password.")
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superusers must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superusers must have is_superuser=True.")

        return self.create_user(username=username, password=password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(max_length=100, unique=True)
    email = models.EmailField(unique=False, blank=True, null=True)
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    SITE_CHOICES = [
        ("robevalley", "Robe Valley"),
        ("greaterhopedowns", "Greater Hope Downs"),
        ("restofeast", "Rest of East"),
        ("restofwest", "Rest of West"),
    ]
    site = models.CharField(
        max_length=100, choices=SITE_CHOICES, blank=True, null=True
    )  # New field for site
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    def __str__(self):
        return self.username
