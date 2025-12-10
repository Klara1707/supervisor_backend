from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from .views import (
    UserViewSet,
    RegisterView,
    me_view,
    UpdateSiteView,
    CustomTokenObtainPairView,
    UsersBySiteView,
    AdminTokenObtainPairView,
    TrainingProgressView,
    DeleteUserView,
)


# API Endpoints Documentation:
#
# POST /register/ - Register a new user
#   Body: { username, email, first_name, last_name, password }
#   Returns: user info or error messages
#
# POST /token/ - Login and get JWT token
#   Body: { username, password }
#   Returns: { access, refresh, user }
#
# POST /admin-token/ - Admin login (superuser only)
#   Body: { username, password }
#   Returns: { access, refresh, user }
#
# GET /me/ - Get current user info
#   Auth: JWT required
#   Returns: { id, username, email }
#
# GET /users/ - List all users (admin only)
#   Auth: JWT required
#   Returns: list of users
#
# GET /training-progress/ - Get all progress for current user
#   Auth: JWT required
#   Returns: { progress_by_popup: { popup_id: [checked_items] } }
#   404 if no progress found
#
# POST /training-progress/ - Save progress for a popup
#   Auth: JWT required
#   Body: { popup_id, checked_items }
#   Returns: updated progress_by_popup

router = DefaultRouter()
router.register(r"users", UserViewSet)

urlpatterns = [
    path("", include(router.urls)),
    path("token/", CustomTokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token_refresh"),
    path("register/", RegisterView.as_view(), name="register"),
    path("users-by-site/", UsersBySiteView.as_view(), name="users_by_site"),
    path("me/", me_view, name="me"),
    path(
        "admin-token/",
        AdminTokenObtainPairView.as_view(),
        name="admin_token_obtain_pair",
    ),
    path(
        "training-progress/", TrainingProgressView.as_view(), name="training_progress"
    ),
    path("delete-user/", DeleteUserView.as_view(), name="delete_user"),
    path("update-site/", UpdateSiteView.as_view(), name="update_site"),
]
