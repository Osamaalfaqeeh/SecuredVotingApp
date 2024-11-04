from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
# from .serializers import CustomAuthTokenSerializer
from django.contrib.auth.hashers import make_password
from .models import Users, Institutions, Authentication, BlacklistedToken
from .serializers import RegisterSerializer, LoginSerializer
from datetime import datetime, timedelta
from django.utils import timezone
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.views import TokenRefreshView
import logging
# Create your views here.

class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            user = validated_data['user']
            refresh_token = validated_data['refresh']
            access_token = validated_data['access']

            # Set token expiration (e.g., 7 days for refresh token)
            expires_at = timezone.now() + timedelta(days=7)

            # Create a record in the Authentication table
            Authentication.objects.create(
                user=user,
                auth_type='JWT',
                auth_token=refresh_token,  # Storing the refresh token
                created_at=datetime.now(),
                expires_at=expires_at
            )

            # Return response with tokens
            return Response({
                'refresh': refresh_token,
                'access': access_token,
                'user_id': user.user_id
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "User registered successfully."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
logger = logging.getLogger(__name__)

class LogoutView(APIView):
    permission_classes = []  # No permission required

    def post(self, request):
        refresh_token = request.data.get("refresh")
        access_token = request.headers.get("Authorization", "").split(" ")[1]
        logger.debug(access_token)

        if not refresh_token:
            return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

        if BlacklistedToken.objects.filter(token=refresh_token).exists():
            return Response({"error": "This refresh token has already been blacklisted."}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Blacklist the access token
            access = AccessToken(access_token)
            BlacklistedToken.objects.create(token=str(access))


            # Blacklist the refresh token
            refresh = RefreshToken(refresh_token)
            BlacklistedToken.objects.create(token=str(refresh))

        except TokenError:
            return Response({"error": "Invalid or expired refresh token"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Successfully logged out"}, status=status.HTTP_200_OK)
    

class CustomTokenRefreshView(TokenRefreshView):
    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get("refresh")
        
        # Check if the refresh token is blacklisted
        if BlacklistedToken.objects.filter(token=refresh_token).exists():
            return Response({"error": "Token has been blacklisted and cannot be refreshed"}, status=status.HTTP_400_BAD_REQUEST)
        
        # If not blacklisted, proceed with the usual refresh process
        return super().post(request, *args, **kwargs)

class ExampleView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Only authenticated users will reach this point
        return Response({"message": "Hello, authenticated user!"})