from django.urls import path
from .views import LoginView, RegisterView, LogoutView, CustomTokenRefreshView, ExampleView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('refresh/', CustomTokenRefreshView.as_view(), name='token_refresh'),
    path('example/', ExampleView.as_view(), name='example')
]