from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_api_key.permissions import HasAPIKey
from .models import BlacklistedToken, Users
import logging

logger = logging.getLogger(__name__)

class CustomJWTAuthentication(JWTAuthentication):
    def authenticate(self, request):
        api_key = request.headers.get('Authorization')
        if api_key:
            # Handle API key authentication if provided
            if not HasAPIKey().has_permission(request, self):
                raise AuthenticationFailed('Invalid API key')
            return None  # If using API key, you might want to skip JWT here
        
        result = super().authenticate(request)
        if result is not None:
            user, token = result
            if not user.is_verified:
                raise AuthenticationFailed("Email not verified. Please verify your email.")
            # Check if the token is blacklisted
            if BlacklistedToken.objects.filter(token=str(token)).exists():
                raise AuthenticationFailed("Token has been blacklisted")
        return result

    def get_user(self, validated_token):
        try:
            # Extract the user_id from the token's claims
            user_id = validated_token.get("user_id")
            user = Users.objects.get(user_id=user_id)
        except Users.DoesNotExist:
            raise AuthenticationFailed("User not found")
        return user

    def get_header(self, request):
        """
        Extracts the 'Authorization' header from the request.
        """
        return request.headers.get("Authorization")

    def get_raw_token(self, header):
        """
        Extracts the token from the 'Authorization' header.
        Assumes format: "Bearer <token>".
        """
        parts = header.split()
        if len(parts) != 2 or parts[0] != "Bearer":
            return None
        return parts[1].strip('"')