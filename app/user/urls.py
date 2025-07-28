from django.urls import path
from .views import (
    RegisterView,
    LoginView,
    ChangePasswordView,
    ForgotPasswordView,
    UserProfileView,
    PublicUserProfileView,
    LogoutView,
)

urlpatterns = [
    # Authentication
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),

    # Profile Management
    path('profile/', UserProfileView.as_view(), name='user_profile'),
    path('users/<str:username>/', PublicUserProfileView.as_view(), name='public_profile'),
]
