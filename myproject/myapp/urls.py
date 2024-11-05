from django.urls import path
from .views import LoginView, RegisterView, LogoutView, CustomTokenRefreshView, ExampleView, activate, activation_success, activation_failed, already_verified

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('example/', ExampleView.as_view(), name='example'),
    path('activate/<uidb64>/<token>/', activate, name='activate'),
    path('activation-success/', activation_success, name='activation_success'),
    path('activation-failed/', activation_failed, name='activation_failed'),
    path('already-verified/', already_verified, name='already_verified'),
]