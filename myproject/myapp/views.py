from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
# from .serializers import CustomAuthTokenSerializer
from django.contrib.auth.hashers import make_password
from .models import Users, Institutions, Authentication
from .serializers import RegisterSerializer, LoginSerializer
from datetime import datetime, timedelta
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
            expires_at = datetime.now() + timedelta(days=7)

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