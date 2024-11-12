from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
# from .serializers import CustomAuthTokenSerializer
from django.contrib.auth.hashers import make_password, check_password
from .models import Users, Institutions, Authentication, BlacklistedToken, Elections, ElectionVotingGroups, VotingGroups, Candidates, VotingGroupMembers, ElectionGroups
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
from .utils import generate_verification_token, verify_token, send_2fa_code
from rest_framework.exceptions import ValidationError
from django.core.cache import cache
from .permissions import IsAdmin
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


class CreateElectionView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]  # Ensure only admins can access this view

    def post(self, request):
        # Get the election data from the request
        serializer = ElectionSerializer(data=request.data)
        if serializer.is_valid():
            # Set the creator of the election to the logged-in admin
            serializer.validated_data['created_by'] = request.user
            election = serializer.save()

            # Handle election icon upload (if you have file handling)
            if 'icon' in request.FILES:
                election.icon = request.FILES['icon']
                election.save()

            # Get the list of selected candidates (user IDs)
            candidate_ids = request.data.get('candidate_ids', [])
            if candidate_ids:
                candidates = Users.objects.filter(user_id__in=candidate_ids)
                for candidate in candidates:
                    # Link each selected user as a candidate for the election
                    Candidates.objects.create(election=election, candidate=candidate)

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

            return Response({
                "detail": "Election created successfully.",
                "election_id": str(election.election_id),
                "title": election.election_name,
            }, status=status.HTTP_201_CREATED)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


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
            if 'icon' in request.FILES:
                election.icon = request.FILES['icon']
            serializer.save()
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

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        # Return only the profile picture URL
        user_data = {
            'profile_photo': user.profile_photo.url if user.profile_photo else None
        }
        return Response(user_data, status=status.HTTP_200_OK)

class ElectionDetailView(APIView):
    permission_classes = [IsAuthenticated]  # Ensure the user is authenticated

    def get(self, request, election_id):
        try:
            election = Elections.objects.get(election_id=election_id)
            # Check if the election is still open based on the end time
            is_open = election.end_time > datetime.now()

            # Fetch candidates related to this election
            candidates = Candidates.objects.filter(election=election)

            # Return election details along with candidates
            election_data = {
                "election_name": election.election_name,
                "description": election.description,
                "end_time": election.end_time,
                "is_open": is_open,  # Whether voting is still open
                "candidates": [
                    {
                        "candidate_id": candidate.id,
                        "candidate_name": f"{candidate.candidate.first_name} {candidate.candidate.last_name}",  # Access user details via the candidate field
                        "bio": candidate.candidate.bio if candidate.candidate.bio else "No bio available",  # Candidate bio from the User model
                        "profile_photo": candidate.candidate.profile_photo.url if candidate.candidate.profile_photo else None  # Candidate profile photo from the User model
                    }
                    for candidate in candidates
                ],
            }

            return Response(election_data, status=200)
        except Elections.DoesNotExist:
            return Response({"detail": "Election not found."}, status=404)

class UpdateAboutView(APIView):
    permission_classes = [IsAuthenticated]

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

    def patch(self, request):
        user = request.user
        phone_number = request.data.get('phone_number')

        if phone_number:
            user.phone_number = phone_number
            user.save()
            return Response({"detail": "Phone number updated successfully."}, status=status.HTTP_200_OK)
        else:
            return Response({"detail": "Phone number is required."}, status=status.HTTP_400_BAD_REQUEST)