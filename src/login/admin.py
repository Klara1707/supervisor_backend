from django.contrib import admin
from .models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "username",
        "first_name",
        "last_name",
        "site",  # Show site in admin list
        "is_active",
        "is_staff",
    )
    search_fields = ("username",)
    list_filter = ("site", "is_active", "is_staff")  # Filter by site
    actions = ["delete_selected"]
