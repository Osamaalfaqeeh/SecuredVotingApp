import base64
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
# from .serializers import CustomAuthTokenSerializer
from django.contrib.auth.hashers import make_password, check_password
from .models import Users, Institutions, Authentication, BlacklistedToken, Elections, ElectionVotingGroups, VotingGroups, Candidates, VotingGroupMembers, ElectionGroups, Votes, \
VotingSession, Logs, Roles, ElectionPosition, CandidatePosition, ReferendumQuestion, ReferendumOption, ReferendumVote, ElectionApproval, WithdrawalToken
from .serializers import RegisterSerializer, LoginSerializer, ElectionSerializer, ProfilePictureSerializer
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
from .utils import generate_verification_token, verify_token, send_2fa_code, generate_anonymous_id, get_client_ip, generate_anonymous_id_for_referendum
from rest_framework.exceptions import ValidationError, PermissionDenied
from django.core.cache import cache
from .permissions import IsAdmin
from django.db import IntegrityError
import secrets
from django.db.models import Count
from myproject import settings
import uuid
from django.http import HttpResponse
from django.contrib import messages
from django.core.files.base import ContentFile
# Create your views here.

logger = logging.getLogger('myapp')

class LoginView(APIView):
    permission_classes = []

    def post(self, request):
        ip_address = get_client_ip(request)
        
        # Log the login attempt (system-level logging using Django logger)
        logger.info(f"Login attempt from IP: {ip_address} for user: {request.data.get('email')}")

        # Log to the database (detailed, custom log for auditing purposes)
        log_entry = Logs(
            user=None,  # None because the user is not authenticated yet
            action="User login attempt",
            status="Pending",
            ip_address=ip_address,
            additional_info={"email": request.data.get("email")}
        )
        log_entry.save()

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
                }, status=status.HTTP_200_OK)
            
            if not user.is_active:
                return Response({
                    "error": "Your account is inactive. Please reset your password to continue.",
                    "reset_password_required": True  # Indicates that the user needs to reset their password
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if user.is_2fa_enabled:
                send_2fa_code(user)
                return Response({
                    "message": "2FA code sent to your email.",
                    "requires_2fa": True,
                    "user_id": user.user_id,
                }, status=status.HTTP_200_OK)
            
            log_entry = Logs(
                user=user,
                action="User login success",
                status="Success",
                ip_address=ip_address
            )
            log_entry.save()
            # Log success with Django logger
            logger.info(f"User {user.email} logged in successfully from IP: {ip_address}")

            refresh_token = validated_data['refresh']
            access_token = validated_data['access']
            user.last_login = timezone.now()
            user.save()
            # Set token expiration (e.g., 7 days for refresh token)
            expires_at = timezone.now() + timedelta(days=7)
            biometric_authenticated = request.data.get('biometric_authenticated', False)
            if biometric_authenticated:
                auth_type_value = 'Biom'
            else:
                auth_type_value = 'JWT'
            # Create a record in the Authentication table
            Authentication.objects.create(
                user=user,
                auth_type=auth_type_value,
                auth_token=refresh_token,  # Storing the refresh token
                created_at=datetime.now(),
                expires_at=expires_at
            )
            role = user.role.role_name
            # Return response with tokens
            return Response({
                'refresh': refresh_token,
                'access': access_token,
                'user_id': user.user_id,
                'role': role
            }, status=status.HTTP_200_OK)

        # If login failed due to invalid serializer data
        log_entry = Logs(
            user=None,
            action="User login attempt",
            status="Failure",
            ip_address=ip_address,
            error_message=str(serializer.errors)
        )
        log_entry.save()
        # Log the failure with Django logger
        logger.error(f"Invalid login attempt for {request.data.get('email')}: {serializer.errors}")

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RegisterView(APIView):
    permission_classes = []

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            send_verification_email(request, user)
            return Response({"message": "User registered successfully, check your email"}, status=status.HTTP_201_CREATED)
        print(serializer.errors)
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


class ToggleBiometricAuthView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def patch(self, request):
        user = request.user  # Get the currently authenticated user
        
        # Check if the user is requesting to enable or disable biometric authentication
        enable_biometric = request.data.get('isBiometricEnabled', None)
        
        if enable_biometric is None:
            return Response({"detail": "No action provided for biometric authentication."}, status=400)
        
        # Update the user's biometric authentication setting
        user.biometric_enabled = enable_biometric
        user.save()

        return Response({
            "detail": f"Biometric authentication {'enabled' if enable_biometric else 'disabled'} successfully."
        }, status=200)


class Toggle2FAView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        enable_2fa = request.data.get("isTwoFactorEnabled")
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
        
        print(request.data);
        user_id = request.data.get("user_id")
        print(code + user_id)
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
            user.last_login = timezone.now()
            user.save()
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
                "user_id": user.user_id,
                "role": user.role.role_name
            }, status=status.HTTP_200_OK)
        
        return Response({"error": "Invalid or expired 2FA code"}, status=status.HTTP_400_BAD_REQUEST)


class CreateElectionView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Ensure only admins can access this view

    def post(self, request):
        ip_address = get_client_ip(request)

        # Log the election creation attempt (system-level logging using Django logger)
        logger.info(f"Admin {request.user.email} is creating an election")

        # Log to the database (detailed, custom log for auditing purposes)
        log_entry = Logs(
            user=request.user,
            action="Create election attempt",
            status="Pending",
            ip_address=ip_address,
            additional_info={"election_name": request.data.get("election_name")}
        )
        log_entry.save()
        # Get the election data from the request
        serializer = ElectionSerializer(data=request.data)
        if serializer.is_valid():
            # Set the creator of the election to the logged-in admin
            serializer.validated_data['created_by'] = request.user
            election = serializer.save()

            # Handle election icon upload (if you have file handling)
            # if 'icon' in request.FILES:
            #     election.icon = request.FILES['icon']
            #     election.save()

            # icon_base64 = request.data.get('icon', None)
            # if icon_base64:
            #     try:
            #         # Decode the Base64 string and save as an image file
            #         format, imgstr = icon_base64.split(';base64,')
            #         ext = format.split('/')[-1]  # Extract file extension
            #         file_name = f"election_icons/{election.election_id}.{ext}"
            #         election.icon.save(file_name, ContentFile(base64.b64decode(imgstr)))
            #     except Exception as e:
            #         raise ValidationError(f"Invalid Base64 image data: {e}")

            icon_base64 = request.data.get('icon', None)
            if icon_base64:
                election.icon = icon_base64  # Store the Base64 string as-is
                election.save()
            
            # Create positions (e.g., President, Vice President)
            position_names = request.data.get('position_names', [])
            for position_name in position_names:
                ElectionPosition.objects.create(election=election, position_name=position_name)
        
            # Create candidates for each position
            candidate_ids = request.data.get('candidate_ids', {})
            for position_name, candidates in candidate_ids.items():
                position = ElectionPosition.objects.get(election=election, position_name=position_name)
                candidates = Users.objects.filter(user_id__in=candidates)
                for candidate in candidates:
                    CandidatePosition.objects.create(election_position=position, candidate=candidate)

            # Get the list of selected voting groups (group IDs)
            group_ids = request.data.get('group_ids', [])
            if group_ids:
                for group_id in group_ids:
                    group = VotingGroups.objects.get(group_id=group_id)  # Get the group by its ID
                    # Link the group to the election
                    ElectionVotingGroups.objects.create(election=election, group=group)


            # Get the list of selected users for direct voting (election groups)
            user_ids = request.data.get('user_ids', [])
            if user_ids:
                for user_id in user_ids:
                    user = Users.objects.get(user_id=user_id)
                    # Link the user to the election via ElectionGroups
                    ElectionGroups.objects.create(election=election, user=user)
            
            # Handle referendum questions
            referendum_questions = request.data.get('referendum_questions', [])
            for question_data in referendum_questions:
                question = ReferendumQuestion.objects.create(
                    election=election,
                    question_text=question_data['question_text'],
                    is_mandatory=question_data.get('is_mandatory', True)
                )
                for option_data in question_data.get('options', []):
                # Ensure that we extract the plain text from the option_data dictionary
                    option_text = option_data.get('option_text', '').strip()
                    if option_text:  # Only create options with non-empty text
                        ReferendumOption.objects.create(
                            question=question,
                            option_text=option_text
                        )
            # Log success in the database
            log_entry = Logs(
                user=request.user,
                action="Create election success",
                status="Success",
                ip_address=ip_address
            )
            log_entry.save()
            # Log success with Django logger
            logger.info(f"Election {election.election_name} created successfully by admin {request.user.email}")

            return Response({
                "detail": "Election created successfully.",
                "election_id": str(election.election_id),
                "title": election.election_name,
            }, status=status.HTTP_201_CREATED)
        
         # Log failure if serializer is invalid
        log_entry = Logs(
            user=request.user,
            action="Create election attempt",
            status="Failure",
            ip_address=ip_address,
            error_message=str(serializer.errors)
        )
        log_entry.save()
        # Log failure with Django logger
        logger.error(f"Election creation failed: {serializer.errors}")
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class GetNonAdminUsersView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Ensure only authenticated admins can access this view

    def get(self, request):
        # Get the requesting user's id (the admin making the request)
        admin_user = request.user
        
        # Fetch all users except the admin
        users = Users.objects.exclude(user_id=admin_user.user_id)  # Exclude the admin user
        
        # Serialize the user data (this can be customized based on the fields you want)
        user_data = []
        for user in users:
            user_data.append({
                'user_id': str(user.user_id),
                'firstname': user.firstname,
                'lastname': user.lastname,
                'email': user.email,
                'profile_photo': request.build_absolute_uri(user.profile_photo.url)
                                    if user.profile_photo
                                    else None # Add profile photo if available # Add profile photo if available
            })

        return Response({'users': user_data}, status=status.HTTP_200_OK)

class CreateGroupView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request):
        # Create the group
        group_name = request.data.get('group_name', 'Default Group')
        group = VotingGroups.objects.create(group_name=group_name, created_by=request.user)

        # Add users to the group from the search results or direct user IDs
        user_ids = request.data.get('user_ids', [])
        if not user_ids:
            return Response({"detail": "Please select at least one user to add to the group."}, status=status.HTTP_400_BAD_REQUEST)

        # Get users from the database based on the selected IDs
        users = Users.objects.filter(user_id__in=user_ids)
        if not users.exists():
            return Response({"detail": "One or more selected users do not exist."}, status=status.HTTP_404_NOT_FOUND)

        for user in users:
            VotingGroupMembers.objects.create(group=group, user=user)  # Link users to the group

        return Response({"detail": f"Group '{group_name}' created and users added successfully."}, status=status.HTTP_201_CREATED)


class AddCandidatesToElectionView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, election_id):
        # Retrieve the election to add candidates to
        try:
            election = Elections.objects.get(election_id=election_id, created_by=request.user)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve selected users and add them as candidates
        user_ids = request.data.get('user_ids', [])
        if not user_ids:
            return Response({"detail": "Please select at least one user to be a candidate."}, status=status.HTTP_400_BAD_REQUEST)

        users = Users.objects.filter(user_id__in=user_ids)
        if not users.exists():
            return Response({"detail": "One or more selected users do not exist."}, status=status.HTTP_404_NOT_FOUND)

        # Add selected users as candidates in the election
        for user in users:
            Candidates.objects.create(candidate=user, election=election)

        return Response({"detail": "Candidates successfully added to the election."}, status=status.HTTP_201_CREATED)
    

class EditElectionView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def put(self, request, election_id):
        try:
            election = Elections.objects.get(election_id=election_id, created_by=request.user)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=status.HTTP_404_NOT_FOUND)

        # Update election details
        serializer = ElectionSerializer(election, data=request.data, partial=True)
        if serializer.is_valid():
            # Update election icon if a new one is provided
            if 'icon' in request.data:
                election.icon = request.data['icon']

            # Save basic election data
            serializer.save()


            position_names = request.data.get('position_names', [])
            ElectionPosition.objects.filter(election=election).delete()
            for position_name in position_names:
                
                ElectionPosition.objects.create(election=election, position_name=position_name)
        
            # Create candidates for each position
            candidate_ids = request.data.get('candidate_ids', {})
            for position_name, candidates in candidate_ids.items():
                position = ElectionPosition.objects.get(election=election, position_name=position_name)
                CandidatePosition.objects.filter(election_position=position).delete()
                position = ElectionPosition.objects.get(election=election, position_name=position_name)
                candidates = Users.objects.filter(user_id__in=candidates)
                for candidate in candidates:
                    CandidatePosition.objects.create(election_position=position, candidate=candidate)
            

            # Handle referendum questions
            if 'referendum_questions' in request.data:
                ReferendumQuestion.objects.filter(election=election).delete()
                for question_data in request.data['referendum_questions']:
                    question = ReferendumQuestion.objects.create(
                        election=election,
                        question_text=question_data['question_text'],
                        is_mandatory=question_data.get('is_mandatory', True)
                    )
                    if 'options' in question_data:
                        for option_data in question_data['options']:
                            ReferendumOption.objects.create(
                                question=question,
                                option_text=option_data['option_text']
                            )

            # Handle eligible users
            if 'user_ids' in request.data:
                ElectionGroups.objects.filter(election=election).delete()
                for user_id in request.data['user_ids']:
                    user = Users.objects.get(user_id=user_id)
                    ElectionGroups.objects.create(user=user, election=election)

            return Response({"detail": "Election updated successfully."}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class AllowGroupToVoteView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, election_id):
        # Retrieve election
        try:
            election = Elections.objects.get(election_id=election_id, created_by=request.user)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve the group and link to the election
        group_ids = request.data.get('group_ids', [])
        if not group_ids:
            return Response({"detail": "No groups provided."}, status=status.HTTP_400_BAD_REQUEST)

        for group_id in group_ids:
            try:
                group = VotingGroups.objects.get(group_id=group_id)
                # Link the group to the election for voting
                ElectionVotingGroups.objects.create(election=election, group=group)
            except VotingGroups.DoesNotExist:
                return Response({"detail": f"Group with ID {group_id} not found."}, status=status.HTTP_404_NOT_FOUND)

        return Response({"detail": "Groups successfully linked to the election for voting."}, status=status.HTTP_200_OK)


class ListGroupsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Retrieve all groups
        groups = VotingGroups.objects.all()
        
        # Prepare data to return
        group_data = [{
            "group_id": group.group_id,
            "group_name": group.group_name,
            "members_count": group.votinggroupmembers_set.count(),  # Get number of members in the group
            "created_by": group.created_by.firstname,
        } for group in groups]

        return Response({"groups": group_data}, status=status.HTTP_200_OK)


class ListUsersInGroupView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, group_id):
        # Retrieve the group based on the group_id
        try:
            group = VotingGroups.objects.get(group_id=group_id)
        except VotingGroups.DoesNotExist:
            return Response({"detail": "Group not found."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve all users in this group via VotingGroupMembers
        users_in_group = VotingGroupMembers.objects.filter(group=group)

        # Prepare user data to return
        user_data = [{
            "user_id": member.user.user_id,
            "first_name": member.user.firstname,
            "last_name": member.user.lastname,
            "profile_photo": member.user.profile_photo.url if member.user.profile_photo else None,  # Assuming profile_picture is the field
        } for member in users_in_group]

        return Response({"users": user_data}, status=status.HTTP_200_OK)
    

class SearchUsersByName(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        query = request.query_params.get('name', '')  # Get the search query from the request
        if not query:
            return Response({"detail": "Please provide a name to search."}, status=400)

        # Search for users based on the name
        users = Users.objects.filter(first_name__icontains=query) | Users.objects.filter(last_name__icontains=query)

        # Prepare user data for the response
        user_data = [{
            "user_id": user.user_id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "profile_photo": user.profile_picture.url if user.profile_picture else None
             } for user in users]

        return Response({"users": user_data}, status=200)


class EditPersonalInformationView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response({
            # "success": True,
            # "data": {
            
                "first_name": user.firstname,
                "last_name": user.lastname,
                "phone_number": user.phone_number,  # Assuming `phone_number` is in a related profile model
            
        },status=200)

    def post(self, request):
        user = request.user
        user.firstname = request.data.get('first_name', user.firstname)
        user.lastname = request.data.get('last_name', user.lastname)
        user.phone_number = request.data.get('phone_number', user.phone_number)
        user.save()
        return Response({
            # "success": True,
            "message": "Profile updated successfully"
        })


class DeleteAccountView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        confirmation = request.data.get('confirmation')
        if confirmation.lower() == 'delete':
            user = request.user
            user.deleted = True
            user.is_active = False
            user.is_verified = False
            user.is_2fa_enabled = False
            user.biometric_enabled = False
            user.save()
            return Response({'success': True, 'message': 'Account deleted successfully.'})
        return Response({'success': False, 'message': 'Invalid confirmation.'})


class UpdateProfilePictureView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can update their profile picture

    def put(self, request):
        user = request.user  # Get the authenticated user
        
        # Serialize the incoming data
        serializer = ProfilePictureSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            # Save the new profile picture
            serializer.save()
            return Response({"detail": "Profile picture updated successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request):
        user = request.user

        # Check if the user has a profile picture
        if user.profile_photo:
            user.profile_photo.delete(save=False)  # Delete the image file
            user.profile_photo = None
            user.save()
            return Response({"detail": "Profile picture deleted successfully."}, status=status.HTTP_200_OK)

        return Response({"detail": "No profile picture to delete."}, status=status.HTTP_400_BAD_REQUEST)

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Return only the profile picture URL
       
        profile_photo_url = (
            request.build_absolute_uri(user.profile_photo.url)
            if user.profile_photo
            else None
        )
        print(profile_photo_url)
        user_data = {
            'profilePhoto': profile_photo_url,
            'isBiometricEnabled': user.biometric_enabled,
            'isTwoFactorEnabled': user.is_2fa_enabled
        }
        return Response(user_data, status=status.HTTP_200_OK)

class ElectionDetailView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request, election_id):
        try:
            election = Elections.objects.get(election_id=election_id)
            print(election_id)
            # Check if the election is still open based on the end time
            is_open = election.end_time > timezone.now()

            # Fetch positions related to this election
            positions = ElectionPosition.objects.filter(election=election)

            referendum_questions = ReferendumQuestion.objects.filter(election=election)
            print(referendum_questions);
            print(positions)
            election_data = {
                "election_name": election.election_name,
                "description": election.description,
                "start_time": election.start_time,
                "end_time": election.end_time,
                "is_launched": election.is_launched,
                "is_open": is_open,  # Whether voting is still open
                "user_id": request.user.user_id,
                "positions": [
                    {
                        "id": position.id,
                        "position_name": position.position_name,
                        "candidates": [
                            {
                                "candidate_id": candidate_position.candidate.user_id,
                                "candidate_name": f"{candidate_position.candidate.firstname} {candidate_position.candidate.lastname}",
                                "bio": candidate_position.candidate.bio if candidate_position.candidate.bio else "No bio available",
                                "profile_photo": request.build_absolute_uri(candidate_position.candidate.profile_photo.url)
                                    if candidate_position.candidate.profile_photo
                                    else None
                            }
                            for candidate_position in CandidatePosition.objects.filter(election_position=position)
                        ]
                    }
                    for position in positions
                ],
                "referendum_questions": [
                    {
                        "id": question.id,
                        "question_text": question.question_text,
                        "options": [
                            {"id": option.id, "option_text": option.option_text}
                            for option in ReferendumOption.objects.filter(question=question)
                        ],
                    }
                    for question in referendum_questions
                ],
            }
            print(election_data)
            return Response(election_data, status=200)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=404)

class LaunchElectionView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, election_id):
        try:
            election = Elections.objects.get(election_id=election_id)

            if election.is_launched:
                return Response({'success': False, 'detail':'Election has already been launched.'}, status=400)

            election.is_launched = True
            election.save()

            return Response({'success': True, 'detail': 'Election launched successfully.'}, status=200)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=404)

class ElectionEditView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Ensure only admins can access this view

    def get(self, request, election_id):
        try:
            # Retrieve the election based on election_id
            election = Elections.objects.get(election_id=election_id)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=status.HTTP_404_NOT_FOUND)

    # Fetch the positions for the election
        positions = election.positions.all()

        # Prepare data for positions and their candidates
        positions_data = [
            {
                "position_name": position.position_name,
                "position_id": str(position.id),
                "description": position.description,
                "candidates": [
                    {
                        "user_id": str(candidate.candidate.user_id),
                        "candidate_name": f"{candidate.candidate.firstname} {candidate.candidate.lastname}",
                        "candidate_email": candidate.candidate.email,
                    }
                    for candidate in position.candidates.all()
                ],
            }
            for position in positions
        ]

        # Fetch users who can vote
        eligible_users = ElectionGroups.objects.filter(election=election)
        users_who_can_vote = [user.user for user in eligible_users]

        # Fetch referendum questions
        referendum_questions = ReferendumQuestion.objects.filter(election=election)

        # Serialize the election data
        election_data = {
            "election_id": str(election.election_id),
            "election_name": election.election_name,
            "description": election.description,
            "start_time": election.start_time.isoformat(),
            "end_time": election.end_time.isoformat(),
            "icon": election.icon,
            "allow_self_vote": election.allow_self_vote,
            "positions": positions_data,
            "users_who_can_vote": [
                {
                    "user_id": str(user.user_id),
                    "user_name": f"{user.firstname} {user.lastname}",
                    "user_email": user.email,
                }
                for user in users_who_can_vote
            ],
            "referendum_questions": [
                {
                    "question_text": question.question_text,
                    "options": [
                        {"option_text": option.option_text}
                        for option in ReferendumOption.objects.filter(question=question)
                    ],
                }
                for question in referendum_questions
            ],
        }

        return Response({"election": election_data}, status=status.HTTP_200_OK)


class ActiveElectionsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        # Fetch active elections (you can add your custom filters if needed)
        elections = Elections.objects.filter(is_active=True,end_time__gt=timezone.now())  # Only active elections
        
        if not elections:
            return Response({"message": "No active elections available."}, status=status.HTTP_200_OK)

        # Serialize the election data
        election_data = []
        
        for election in elections:
            candidates = Candidates.objects.filter(election=election.election_id)
            election_data.append({
                "election_id": str(election.election_id),
                "election_name": election.election_name,
                "description": election.description,
                "start_time": election.start_time,
                "end_time": election.end_time,
                "icon": election.icon,  # You can also include a URL for the icon if it's uploaded
                "participants": candidates.count(),  # For example, the number of candidates
                "time_left": str(election.end_time - timezone.localtime()),  # Calculate time left
            })

        return Response({"elections": election_data}, status=status.HTTP_200_OK)
    
class DeleteElectionView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Ensure only admins can access this view

    def delete(self, request, election_id):
        try:
            # Retrieve the election
            election = Elections.objects.get(election_id=election_id)

            # Check if the election exists
            if not election:
                return Response({"detail": "Election not found."}, status=status.HTTP_404_NOT_FOUND)

            # Optionally, delete related models (if needed)
            # You can choose to delete candidates, election groups, or handle them differently
            Candidates.objects.filter(election=election).delete()  # Delete all candidates related to this election
            ElectionGroups.objects.filter(election=election).delete()  # Delete all groups related to this election

            # Delete the election itself
            election.delete()

            return Response({"detail": "Election and associated data deleted successfully."}, status=status.HTTP_204_NO_CONTENT)
        
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=status.HTTP_404_NOT_FOUND)
        

class UpdateAboutView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        return Response({"about": user.bio}, status=status.HTTP_200_OK)


    def patch(self, request):
        user = request.user  # The logged-in user

        # Get the bio from the request or keep the current value if not provided
        bio = request.data.get('bio', user.bio)

        # Update the user's bio field
        user.bio = bio
        user.save()

        return Response({"detail": "Bio updated successfully."}, status=status.HTTP_200_OK)
    

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        user = request.user  # The logged-in user
        current_password = request.data.get('current_password')
        new_password = request.data.get('new_password')

        # Check if the current password is correct
        if not check_password(current_password, user.password_hash):
            return Response({"detail": "Current password is incorrect."}, status=status.HTTP_400_BAD_REQUEST)

        # Set the new password and hash it
        user.password_hash = make_password(new_password)
        user.save()  # Save the user with the new password

        return Response({"detail": "Password updated successfully."}, status=status.HTTP_200_OK)
    
class EditPhoneNumberView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self,request):
        user = request.user
        return Response({"phoneNumber": user.phone_number}, status=status.HTTP_200_OK)

    def patch(self, request):
        user = request.user
        phone_number = request.data.get('phone_number')

        if phone_number:
            user.phone_number = phone_number
            user.save()
            return Response({"detail": "Phone number updated successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Phone number is required."}, status=status.HTTP_400_BAD_REQUEST)
        

class CastVoteView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def post(self, request, election_id):
        user = request.user  # Get the currently authenticated user

        # Check if the election exists
        try:
            election = Elections.objects.get(election_id=election_id)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=404)

        # Ensure the election is active
        if not election.is_active:
            raise PermissionDenied("Voting is not allowed for this election or it has ended.")

        # Ensure the user is eligible to vote in this election
        if not self.is_user_eligible(user, election):
            raise PermissionDenied("You are not eligible to vote in this election.")

        # Get the position the user is voting for
        position_id = request.data.get('position_id')
        try:
            position = ElectionPosition.objects.get(id=position_id, election=election)
        except ElectionPosition.DoesNotExist:
            return Response({"detail": "Position not found."}, status=404)

        anonymous_id = generate_anonymous_id(user.user_id, election_id, position_id)

        # Check if the user has already voted for this position
        try:
            session = VotingSession.objects.get(anonymous_id=anonymous_id)
            if session.has_voted:
                return Response({"detail": "You have already voted for this position."}, status=400)
        except VotingSession.DoesNotExist:
            # If no session exists, create a new one
            session = VotingSession.objects.create(anonymous_id=anonymous_id)

        # Get the candidate the user wants to vote for
        candidate_id = request.data.get('candidate_id')
        try:
            candidate = Users.objects.get(user_id=candidate_id)
        except Users.DoesNotExist:
            return Response({"detail": "Candidate not found."}, status=404)

        # Check if the candidate is a valid candidate for this position in this election
        if not CandidatePosition.objects.filter(candidate=candidate, election_position=position).exists():
            return Response({"detail": "The selected candidate is not part of this position."}, status=400)

        # Generate a unique vote token for anonymity
        vote_token = secrets.token_hex(32)

        # Cast the vote and store it in the database
        try:
            vote = Votes.objects.create(
                election=election,
                candidate=candidate,
                election_position=position,
                vote_token=vote_token,
                timestamp=timezone.now(),
            )
        except IntegrityError:
            return Response({"detail": "An error occurred while saving your vote."}, status=500)

        # Mark this user as having voted for the position
        session.has_voted = True
        session.save()

        return Response({"detail": "Vote cast successfully."}, status=201)

    def is_user_eligible(self, user, election):
        
        eligible_groups = ElectionVotingGroups.objects.filter(election=election)
        
        # Check if the user is in any of the eligible voting groups
        for group in eligible_groups:
            if VotingGroupMembers.objects.filter(group_id=group.group, user=user).exists():
                return True
            
        if ElectionGroups.objects.filter(election=election, user=user).exists():
            return True
        # If no eligible group found for the user
        return False
    

class SubmitReferendumView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, election_id):
        try:
            election = Elections.objects.get(election_id=election_id)

            # Ensure the election is still open
            if election.end_time < timezone.now():
                return Response(
                    {"detail": "This election is closed."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            user_id = request.user
            anonymous_id = generate_anonymous_id_for_referendum(user_id, election_id)

            # Check if the user has already submitted
            existing_votes = ReferendumVote.objects.filter(anonymous_id=anonymous_id)
            if existing_votes.exists():
                return Response(
                    {"detail": "You have already submitted your referendum votes."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            # Get the referendum answers from the request
            referendum_answers = request.data.get('answers', [])
            if not isinstance(referendum_answers, list):
                return Response(
                    {"detail": "Invalid format for referendum answers."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            print(referendum_answers)
            # Save the referendum votes
            for answer in referendum_answers:
                question_id = answer.get('question_id')
                selected_option = answer.get('answer')

                if not question_id or not selected_option:
                    return Response(
                        {"detail": "Both question_id and answer are required."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                 # Ensure the question exists
                try:
                    question = ReferendumQuestion.objects.get(id=question_id)
                except ReferendumQuestion.DoesNotExist:
                    return Response(
                        {"detail": f"Question with ID {question_id} not found."},
                        status=status.HTTP_400_BAD_REQUEST
                    )
                
                ReferendumVote.objects.create(
                    anonymous_id = anonymous_id,
                    question_id=question,
                    selected_option=selected_option
                )
                print("after creating")

            return Response({"detail": "Referendum votes submitted successfully."}, status=status.HTTP_201_CREATED)

        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response(
                {"detail": f"An error occurred: {str(e)}"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ElectionPositionsView(APIView):
    def get(self, request, election_id):
        positions = ElectionPosition.objects.filter(election_id=election_id)
        data = [
            {"position_name": position.position_name, "position_id": position.id}
            for position in positions
        ]
        return Response(data)
    

class CheckEligibilityView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure only authenticated users can check eligibility

    def get(self, request, election_id):
        user = request.user

        # Retrieve the election
        try:
            election = Elections.objects.get(id=election_id)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=404)

        # Check if the user is eligible to vote (e.g., is part of an eligible group or election)
        if not VotingGroups.objects.filter(election=election, users=user).exists():
            raise PermissionDenied("You are not eligible to vote in this election.")

        return Response({"detail": "You are eligible to vote in this election."}, status=200)
    
class ElectionWinnerView(APIView):
    def get(self, request, election_id):
        # Retrieve the election based on the given election_id
        try:
            election = Elections.objects.get(election_id=election_id)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=404)
        
        # Count the votes for each candidate in the election
        vote_counts = (Votes.objects.filter(election=election)
            .values('candidate')  # Group by candidate
            .annotate(vote_count=Count('vote_id'))  # Count votes for each candidate
            .order_by('-vote_count')  # Order by vote count in descending order
        )

        # If there are no votes, return a message
        if not vote_counts:
            return Response({"detail": "No votes have been cast in this election."}, status=200)

        # Get the candidate with the most votes
        winner = vote_counts[0]

        # Retrieve the candidate object
        winning_candidate = Users.objects.get(user_id=winner['candidate'])

        # Return the result
        return Response({
            "election_name": election.election_name,
            "winner": {
                "candidate_name": f"{winning_candidate.firstname} {winning_candidate.lastname}",
                "votes": winner['vote_count']
            }
        }, status=200)


class CheckVotingStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, election_id):
        user = request.user

        # Generate anonymous voting session ID
        anonymous_id = generate_anonymous_id(user.user_id, election_id)

        # Check if the user has already voted
        try:
            session = VotingSession.objects.get(anonymous_id=anonymous_id)
            if session:
                if session.has_voted:
                    return Response({"has_voted": True}, status=200)
        except VotingSession.DoesNotExist:
            pass

        return Response({"has_voted": False}, status=200)


class AdminInactiveElectionsView(APIView):
    permission_classes = [IsAuthenticated,IsAdmin]  # Add any additional permission checks as required

    def get(self, request):
        # Retrieve all inactive elections
        elections = Elections.objects.filter(is_active=True,end_time__lt = timezone.now())

        # Prepare the response data
        elections_data = []
        for election in elections:
            # Get the winner by fetching the candidate with the most votes
            winner_data = None
            winner_votes = 0

            # Fetch the candidates for the election from the Candidates model
            candidates = Candidates.objects.filter(election=election)

            if candidates.exists():
                winner = None
                for candidate in candidates:
                    # Get the total votes for each candidate
                    total_votes = Votes.objects.filter(election=election, candidate=candidate.candidate).count()

                    # Determine the winner by checking the highest vote count
                    if total_votes > winner_votes:
                        winner_votes = total_votes
                        winner = candidate.candidate

                if winner:
                    # Add the winner's details (name, profile photo, and number of votes)
                    winner_data = {
                        "name": f"{winner.firstname} {winner.lastname}",
                        "profile_photo": winner.profile_photo.url if winner.profile_photo else None,
                        "votes": winner_votes,
                    }

            # Prepare election details to return
            elections_data.append({
                "election_id": str(election.election_id),
                "election_name": election.election_name,
                "description": election.description,
                "start_time": election.start_time.isoformat(),
                "end_time": election.end_time.isoformat(),  # Ensure the time is in ISO format
                "winner": winner_data
            })
        return Response({"elections": elections_data}, status=status.HTTP_200_OK)
    
class InactiveElectionsView(APIView):
    permission_classes = [IsAuthenticated]  # Add any additional permission checks as required

    def get(self, request):
        # Retrieve all inactive elections
        elections = Elections.objects.filter(is_active=False)
        
        # Prepare the response data
        elections_data = []
        for election in elections:
            # Get the winner by fetching the candidate with the most votes
            winner_data = None
            winner_votes = 0

            # Fetch the candidates for the election from the Candidates model
            candidates = Candidates.objects.filter(election=election)

            if candidates.exists():
                winner = None
                for candidate in candidates:
                    # Get the total votes for each candidate
                    total_votes = Votes.objects.filter(election=election, candidate=candidate.candidate).count()

                    # Determine the winner by checking the highest vote count
                    if total_votes > winner_votes:
                        winner_votes = total_votes
                        winner = candidate.candidate

                if winner:
                    # Add the winner's details (name, profile photo, and number of votes)
                    winner_data = {
                        "name": f"{winner.firstname} {winner.lastname}",
                        "profile_photo": winner.profile_photo.url if winner.profile_photo else None,
                        "votes": winner_votes,
                    }
            try:
                approved_election = ElectionApproval.objects.get(election=election)
                # Prepare election details to return
                elections_data.append({
                    "election_id": str(election.election_id),
                    "election_name": election.election_name,
                    "description": election.description,
                    "start_time": election.start_time.isoformat(),
                    "end_time": election.end_time.isoformat(),  # Ensure the time is in ISO format
                    "winner": winner_data
                })
            except:
                continue

        return Response({"elections": elections_data}, status=status.HTTP_200_OK)


class AdminElectionResultView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Admin-only access

    def get(self, request, election_id):
        try:
            # Fetch the election and ensure it's inactive
            election = Elections.objects.get(election_id=election_id, is_active=True, end_time__lt = timezone.now())

            # Fetch all positions for the election
            positions = ElectionPosition.objects.filter(election=election)
            positions_data = []

            for position in positions:
                # Fetch all candidates for the position
                candidates = CandidatePosition.objects.filter(election_position=position)

                # Fetch votes and group by candidate
                votes_count = Votes.objects.filter(election_position=position).values(
                    'candidate__user_id'
                ).annotate(votes=Count('vote_id'))

                # Convert votes_count to a dictionary for quick lookup
                votes_dict = {vote['candidate__user_id']: vote['votes'] for vote in votes_count}

                # Total votes for the position
                total_votes = sum(votes_dict.values())

                # Prepare candidates data
                candidates_data = []
                for candidate in candidates:
                    user = candidate.candidate
                    votes = votes_dict.get(user.user_id, 0)  # Default to 0 if no votes
                    candidates_data.append({
                        "candidate_id": str(user.user_id),
                        "candidate_name": f"{user.firstname} {user.lastname}",
                        "votes": votes,
                        "percentage": round((votes / total_votes) * 100, 2) if total_votes > 0 else 0.0,
                        "profile_photo": request.build_absolute_uri(user.profile_photo.url)
                        if user.profile_photo else None,
                    })

                # Sort candidates by votes (highest to lowest)
                candidates_data.sort(key=lambda x: x['votes'], reverse=True)

                positions_data.append({
                    "position_name": position.position_name,
                    "candidates": candidates_data,
                })

            # Fetch referendum questions and results
            referendum_questions = ReferendumQuestion.objects.filter(election=election)
            referendum_data = []
            for question in referendum_questions:
                options = ReferendumOption.objects.filter(question=question)
                total_votes = ReferendumVote.objects.filter(question_id=question).count()

                options_data = []
                for option in options:
                    votes = ReferendumVote.objects.filter(
                        question_id=question, selected_option=option.option_text
                    ).count()
                    options_data.append({
                        "option_id": option.id,
                        "option_text": option.option_text,
                        "votes": votes,
                        "percentage": round((votes / total_votes) * 100, 2) if total_votes > 0 else 0.0,
                    })

                referendum_data.append({
                    "question_id": question.id,
                    "question_text": question.question_text,
                    "options": options_data,
                })

            return Response({
                "election_id": str(election.election_id),
                "election_name": election.election_name,
                "start_time": election.start_time,
                "end_time": election.end_time,
                "description": election.description,
                "positions": positions_data,
                "referendum": referendum_data,
            }, status=status.HTTP_200_OK)

        except Elections.DoesNotExist:
            return Response({"detail": "Election not found or still active."}, status=status.HTTP_404_NOT_FOUND)

class ApproveElectionResultsView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def post(self, request, election_id):
        try:
            election = Elections.objects.get(election_id=election_id, is_active=True, end_time__lt = timezone.now())
            approved_options = request.data.get("approved_options", [])

            if not approved_options:
                return Response({"detail": "No options selected."}, status=status.HTTP_400_BAD_REQUEST)

            # Save or update the approval
            ElectionApproval.objects.update_or_create(
                election=election,
                defaults={
                    "approved_options": approved_options,
                    "approved_by": request.user,
                },
            )
            election.is_active = False
            election.save()

            return Response({"success": True, "message": "Election results approved."}, status=status.HTTP_200_OK)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found or still active."}, status=status.HTTP_404_NOT_FOUND)

class UserElectionResultView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, election_id):
        try:
            # Retrieve the specific election (inactive ones)
            election = Elections.objects.get(election_id=election_id, is_active=False)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found or active."}, status=status.HTTP_404_NOT_FOUND)

        # Fetch admin-approved options
        try:
            approval = ElectionApproval.objects.get(election=election)
            approved_options = approval.approved_options
        except ElectionApproval.DoesNotExist:
            return Response({"detail": "Results not yet approved by admin."}, status=status.HTTP_403_FORBIDDEN)

        # Initialize response data
        response_data = {
            "election_name": election.election_name,
            "description": election.description,
            "start_time": election.start_time,
            "end_time": election.end_time,
            "is_approved": True
        }

        # Process approved options for positions and candidates
        if "All Candidates" in approved_options or "Top 3 Candidates" in approved_options or "Voting Percentage" in approved_options or "Winner Candidate" in approved_options:
            positions_data = []
            positions = ElectionPosition.objects.filter(election=election)

            for position in positions:
                candidates_data = []
                candidates = CandidatePosition.objects.filter(election_position=position)

                total_position_votes = Votes.objects.filter(election=election, election_position=position).count()

                for candidate_position in candidates:
                    candidate_dict = {}
                    candidate = candidate_position.candidate
                    candidate_votes = Votes.objects.filter(election=election, candidate=candidate, election_position=position).count()
                    voting_percentage = (candidate_votes / total_position_votes) * 100 if total_position_votes > 0 else 0

                    candidate_dict = {
                        "candidate_id": str(candidate.user_id),
                        "candidate_name": f"{candidate.firstname} {candidate.lastname}",
                        "profile_photo": request.build_absolute_uri(candidate.profile_photo.url)
                                    if candidate.profile_photo
                                    else None,
                    }
                    
                    
                    if "Number of Voters" in approved_options:
                        candidate_dict["votes"] =  candidate_votes
                    
                    if "Voting Percentage" in approved_options:
                        candidate_dict["voting_percentage"] =  round(voting_percentage, 2)
                    
                    candidates_data.append(candidate_dict)

                position_data = {
                    "position_name": position.position_name,
                    "description": position.description,
                    "candidates": candidates_data
                }

                # Include only top 3 candidates if option is approved
                winnerCandidate = ''
                if "Top 3 Candidates" in approved_options:
                    candidates_data_with_votes = []
    
                    for candidate in candidates_data:
                        # Recalculate the votes for each candidate if "Number of Voters" is not approved
                        # print(candidate)
                        candidate_votes = candidate.get('votes', None)
                        candidate_id = candidate.get("candidate_id")
                        if candidate_votes is None:  # Recalculate votes if not available
                            candidate_votes = Votes.objects.filter(election=election, candidate_id=candidate_id, election_position=position).count()
                        
                        # Add the votes temporarily for sorting purposes, but not in the final response
                        # candidate['votes'] = candidate_votes
                        temp_candidate = candidate.copy()
                        temp_candidate[
                        "votes"] =  candidate_votes
                    
                        candidates_data_with_votes.append(temp_candidate)

                    # Now sort by votes and take top 3 (excluding vote count from the response)
                    candidates_data_with_votes.sort(key=lambda temp_candidate: temp_candidate.get('votes', 0), reverse=True)
                    
                    top_candidates = []
                    for temp_candidate1 in candidates_data_with_votes[:3]:
                        candidate_id = temp_candidate1["candidate_id"]
                        
                        # Find the candidate in the original data (without votes)
                        original_candidate_data = next(candidate for candidate in candidates_data if candidate["candidate_id"] == candidate_id)
                        top_candidates.append(original_candidate_data)
                    winnerCandidate = candidates_data_with_votes[0]


                    position_data["candidates"] = top_candidates  # Limit to top 3 candidates

                # Include winner candidate if option is approved
                if "Winner Candidate" in approved_options:
                    top_candidate =  winnerCandidate
                    position_data["winner"] = top_candidate

                positions_data.append(position_data)

            response_data["positions"] = positions_data

        # Add number of voters if approved
        if "Number of Voters" in approved_options:
            voter_count = Votes.objects.filter(election=election).count()
            response_data["voter_count"] = voter_count

        # Add anonymous referendum results if approved
        if "Anonymous Referendum Results" in approved_options:
            referendum_results = []
            referenda_questions = ReferendumQuestion.objects.filter(election=election)

            for question in referenda_questions:
                options = ReferendumOption.objects.filter(question=question)
                option_results = []

                for option in options:
                    vote_count = ReferendumVote.objects.filter(question_id=question, selected_option=option.option_text).count()
                    option_results.append({
                        "option": option.option_text,
                        "votes": vote_count
                    })

                referendum_results.append({
                    "question_id": question.id,
                    "question_text": question.question_text,
                    "results": option_results
                })

            response_data["referendum_results"] = referendum_results
        return Response(response_data, status=status.HTTP_200_OK)

class ForgotPasswordWithOTPView(APIView):
    permission_classes = []

    def post(self, request):
        email = request.data.get("email")
        if not email:
            return Response({"detail": "Email is required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        # Generate a secure 6-digit OTP using the secrets module
        otp = secrets.token_hex(3)  # 6-character OTP (3 bytes)

        # Set OTP expiration time (e.g., 10 minutes from now)
        expires_at = timezone.now() + timedelta(minutes=10)

        # Cache the OTP with an expiration time of 10 minutes
        cache.set(f"otp_{user.user_id}", otp, timeout=600)  # 600 seconds = 10 minutes

        # Prepare the email content using the HTML template
        email_subject = "Password Reset OTP"
        email_message = render_to_string(
            'forgot password/otp.html',  # Path to the template
            {
                'user': user,  # Pass the user context to the template
                'code': otp     # Pass the OTP to the template
            }
        )

        # Send the email with HTML content
        send_mail(
            email_subject,
            email_message,  # HTML content of the email
            settings.DEFAULT_FROM_EMAIL,
            [email],
            html_message=email_message,  # Make sure to set the HTML message as well
        )

        return Response({"detail": "OTP has been sent to your email."}, status=status.HTTP_200_OK)
    

class VerifyOTPView(APIView):
    permission_classes = []

    def post(self, request):
        otp = request.data.get("otp")
        email = request.data.get("email")  # Use the email to get the user_id

        if not otp or not email:
            return Response({"detail": "OTP and email are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user by email to get the user_id
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return Response({"detail": "User with this email does not exist."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve OTP from cache using the user_id
        cached_otp = cache.get(f"otp_{user.user_id}")
        print(cached_otp);
        if cached_otp != otp:
            return Response({"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # OTP is valid, allow user to reset password
        return Response({"detail": "OTP verified successfully. You can now reset your password."}, status=status.HTTP_200_OK)



class ResetPasswordView(APIView):
    permission_classes = []

    def post(self, request):
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")
        email = request.data.get("email")  # We get the email again to get the user_id

        if not otp or not new_password or not email:
            return Response({"detail": "OTP, new password, and email are required."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Fetch the user by email to get the user_id
            user = Users.objects.get(email=email)
        except Users.DoesNotExist:
            return Response({"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND)

        # Retrieve OTP from cache
        cached_otp = cache.get(f"otp_{user.user_id}")

        # Validate OTP
        if cached_otp != otp:
            return Response({"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST)

        # Hash the new password and save
        user.password_hash = make_password(new_password)
        user.save()

        # Delete OTP from cache after use
        cache.delete(f"otp_{user.user_id}")

        return Response({"detail": "Password has been successfully reset."}, status=status.HTTP_200_OK)


class RequestAdminAccessView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        user = request.user  # Get the currently authenticated user

        # Check if the user is already an admin
        if user.role.role_name == 'admin':
            return Response({"message": "You are already an admin."}, status=400)

        # Generate a unique token for the admin request
        token = str(uuid.uuid4())  # Generate a unique token

        # Store the token in the cache with an expiration time (e.g., 24 hours)
        expires_at = timezone.now() + timedelta(hours=24)
        cache.set(f'admin_request_token_{token}', user.user_id, timeout=86400)  # 86400 seconds = 24 hours

        # Send the email to the admin
        admin_email = settings.ADMIN_EMAIL  # Use your admin email from settings
        domain = get_current_site(request).domain
        # Generate the approval link
        approval_link = f"{f'http://{domain}/api/auth'}/approve-admin-access/{token}/"
        email_message = render_to_string(
                'admin/admin_approval_email.html',  # Email template
                {'user': user, 'approval_link': approval_link}
            )
        # Send the email
        send_mail(
            'Admin Access Request',
            email_message,
            'no-reply@yourdomain.com',
            [admin_email],
            html_message=email_message,
            fail_silently=False,
        )

        return Response({"Admin access request sent for approval."}, status=201)


def ApproveAdminAccessView(request, token):
    print(token);
    # Retrieve the user_id from the cache using the token
    user_id = cache.get(f'admin_request_token_{token}')
    print(user_id)
    if not user_id:
        return HttpResponse("Invalid or expired token.", status=400)

    # Retrieve the user object
    try:
        user = Users.objects.get(user_id=user_id)
    except Users.DoesNotExist:
        return HttpResponse("User not found.", status=404)

    # Check if the token has expired (optional, but we could also rely on the cache expiration time)
    if cache.get(f'admin_request_token_{token}') != user_id:
        return HttpResponse("Token has expired.", status=400)

    # Update the user's role to admin
    try:
        admin_role = Roles.objects.get(role_name='admin')  # Assuming you have a role named 'admin'
    except Roles.DoesNotExist:
        return HttpResponse("Admin role not found.", status=404)

    user.role = admin_role
    user.save()

    # Clear the token from the cache after approval
    cache.delete(f'admin_request_token_{token}')
    email_message = render_to_string(
            'admin/admin_approval_confirmation.html',  # Email template
            {'user': user}  # Passing the user object to the email template
        ),
    send_mail(
        'Admin Access Granted',
        email_message,
        'no-reply@yourdomain.com',
        [user.email],
        html_message= email_message,
        fail_silently=False,
    )

    # Redirect to a success page or show a success message
    messages.success(request, f'{user.email} has been granted admin access.')
    return redirect('approve_success')  # Replace with the actual URL name for your success page

def approve_success(request):
    return render(request, 'admin/success.html') 


class RequestWithdrawalView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, election_id):
        try:
            # Ensure the candidate exists in the election
            # candidate = Candidates.objects.get(candidate=request.user, election_id=election_id)
            candidate = request.user
            position_name = request.data.get('position_name')
            election_positions = ElectionPosition.objects.get(election = election_id, position_name = position_name)
            
            is_candidate = CandidatePosition.objects.filter(
            candidate=request.user,
            election_position=election_positions).exists()
            election = Elections.objects.get(election_id = election_id)
            if not is_candidate:
                return Response({"detail": "You are not a candidate for this election."}, status=404)

        except Candidates.DoesNotExist:
            return Response({"detail": "You are not a candidate for this election."}, status=404)

        # Create a token for withdrawal request
        token = WithdrawalToken.objects.create(
            candidate=request.user,
            election=election,
            position_name = election_positions,
        )

        # Generate the URL for admin approval
        approval_url = reverse('handle-withdrawal', kwargs={'token': token.token})
        domain = get_current_site(request).domain
        full_approval_url = f"{f'http://{domain}'}{approval_url}"
        # Send an email to the admin about the withdrawal request
        admin_email = election.created_by.email

        email_message= render_to_string(
                'candidate_withdraw/withdrawal_request_template.html',  # Path to your HTML template
                {'user': request.user, 'election_name': election.election_name, 'approval_link': full_approval_url}
            )
        
        send_mail(
            subject=f"Withdrawal Request for {candidate.firstname}",
            message= email_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[admin_email],
            html_message=email_message,
            fail_silently=False,
        )
        
        return Response({"detail": "Withdrawal request submitted. Admin approval is pending."}, status=200)
    

def HandleWithdrawalRequest(request, token):
    try:
        # Find the withdrawal token
        withdrawal_token = WithdrawalToken.objects.get(token=token)
        
        # Check if the token is expired
        if withdrawal_token.requested_at < timezone.now() - timedelta(hours=24):
            withdrawal_token.delete()
            return render(request, "withdrawal_expired.html")  # Render an expired page
        
        election = withdrawal_token.election
    except WithdrawalToken.DoesNotExist:
        return render(request, "withdrawal_not_found.html")  # Token not found page
    
    Candidates.objects.filter(candidate=withdrawal_token.candidate, election=withdrawal_token.election).delete()
    election_pos = ElectionPosition.objects.filter(election=election, position_name = withdrawal_token.position_name.position_name)
    CandidatePosition.objects.filter(candidate=withdrawal_token.candidate, election_position__in=election_pos).delete()

    # Mark the token as used (approved/rejected)
    withdrawal_token.delete()

    # Redirect to a confirmation page
    return render(request, "candidate_withdraw/withdrawal_processed.html", {"action": 'approve'})