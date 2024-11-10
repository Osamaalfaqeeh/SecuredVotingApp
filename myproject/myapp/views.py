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
from django.core.mail import send_mail,EmailMessage
from django.urls import reverse
from django.template.loader import render_to_string
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from .tokens import account_activation_token
from django.shortcuts import redirect
from django.utils.http import urlsafe_base64_decode
from .utils import generate_verification_token, verify_token, send_2fa_code
from rest_framework.exceptions import ValidationError
from django.core.cache import cache
# Create your views here.

class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            validated_data = serializer.validated_data
            user = validated_data['user']
            if not user.is_verified:
                send_verification_email(request, user)
                # Return a response that indicates email verification is required
                return Response({
                    "error": "Please verify your email before logging in.",
                    "redirect_to": "unverified_page",  # Indicates to redirect in the mobile app
                    "resend_verification": True  # Flag for allowing resend of verification email
                }, status=status.HTTP_403_FORBIDDEN)
            
            if user.is_2fa_enabled:
                send_2fa_code(user)
                return Response({
                    "message": "2FA code sent to your email.",
                    "requires_2fa": True
                }, status=status.HTTP_200_OK)
            
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
            user = serializer.save()
            send_verification_email(request, user)
            return Response({"message": "User registered successfully, check your email"}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
logger = logging.getLogger(__name__)

class LogoutView(APIView):
    permission_classes = []  # No permission required

    def post(self, request):
        refresh_token = request.data.get("refresh")
        access_token = request.headers.get("Authorization", "").split(" ")[1]
        

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
    

def send_verification_email(request, user):
    # Generate the token
    token = generate_verification_token(user.user_id)
    uid = urlsafe_base64_encode(force_bytes(user.user_id))
    
    # Generate the verification link
    domain = get_current_site(request).domain
    verification_link = reverse('activate', kwargs={'uidb64': uid, 'token': token})
    verification_url = f'http://{domain}{verification_link}'
    
    # Send the email
    subject = 'Verify your email'
    message = render_to_string('registration/activation_email.html', {
        'user': user,
        'verification_url': verification_url,
    })
    # Send the email
    email = EmailMessage(
        subject,
        message,
        'noreply@gmail.com',  # Sender's email
        [user.email],  # Recipient's email
    )
    email.content_subtype = "html"  # Main line that ensures HTML content
    email.send()
    # send_mail(subject, message, 'osamaalfaqeeh55@gmail.com', [user.email])


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Users.objects.get(pk=uid)  # Use the custom Users model
    except (TypeError, ValueError, OverflowError, Users.DoesNotExist):
        user = None

    if user is not None and verify_token(token) == str(user.user_id):
        if user.is_verified:
            # If the user is already verified, show a message or redirect
            return redirect('already_verified')  # Redirect to an "already verified" page
        else:
            user.is_verified = True
            user.save()
            return redirect('activation_success')  # A success page after activation
    else:
        return redirect('activation_failed')  # A failure page

def activation_success(request):
    return render(request, 'registration/activation_success.html')  # Success page template

def activation_failed(request):
    return render(request, 'registration/activation_failed.html')  # Failure page template

def already_verified(request):
    return render(request, 'registration/already_verified.html')  # Already verified page template

class UnverifiedPageView(APIView):
    def get(self, request):
        return Response({"message": "Please verify your email to access the app."})

class ResendVerificationEmailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        if not user.is_verified:
            send_verification_email(request, user)
            return Response({"message": "Verification email resent."})
        return Response({"error": "Email is already verified."}, status=400)

class CheckVerificationStatus(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            "is_verified": user.is_verified
        }, status=200)


class Toggle2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        enable_2fa = request.data.get("enable_2fa")
        user = request.user
        user.is_2fa_enabled = enable_2fa
        user.save()
        return Response({
            "message": "2FA has been updated.",
            "is_2fa_enabled": user.is_2fa_enabled
        }, status=status.HTTP_200_OK)


class Verify2FACodeView(APIView):
    permission_classes = []

    def post(self, request):
        code = request.data.get("code")
        if not code:
            return Response({"error": "2FA code is required."}, status=status.HTTP_400_BAD_REQUEST)
        
        user_id = request.data.get("user_id")
        # user = request.user
        user = Users.objects.get(user_id=user_id)
        # Retrieve the code from cache
        logger.debug(code)
        cached_code = cache.get(f"2fa_code_{user.user_id}")
        logger.debug(cached_code)
        if cached_code and cached_code == code:
            
            # Code matches, so login is successful
            refresh_token = RefreshToken.for_user(user)
            access_token = refresh_token.access_token
            expires_at = timezone.now() + timedelta(days=7)

            cache.delete(f"2fa_code_{user_id}")  # Remove the code after successful verification
            # Generate and return tokens or other authentication data as needed

            Authentication.objects.create(
                user=user,
                auth_type='2FA',
                auth_token=str(refresh_token),
                created_at=timezone.now(),
                expires_at=expires_at,
                is_active=True,
            )

            return Response({
                "refresh": str(refresh_token),
                "access": str(access_token),
                "user_id": user.user_id
            }, status=status.HTTP_200_OK)
        
        return Response({"error": "Invalid or expired 2FA code"}, status=status.HTTP_400_BAD_REQUEST)

# class VerifyEmailView(APIView):
#     def get(self, request, token):
#         try:
#             data = signing.loads(token, salt="email-verification-salt", max_age=86400)  # Expires in 24 hours
#             user = Users.objects.get(user_id=data["user_id"])
#             user.is_verified = True
#             user.save()
#             return Response({"message": "Email verified successfully!"}, status=status.HTTP_200_OK)
#         except signing.BadSignature:
#             return Response({"error": "Invalid or expired token"}, status=status.HTTP_400_BAD_REQUEST)