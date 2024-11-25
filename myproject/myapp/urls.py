from django.urls import path
from .views import LoginView, RegisterView, LogoutView, CustomTokenRefreshView, ExampleView, activate, activation_success, activation_failed, already_verified,\
      UnverifiedPageView, ResendVerificationEmailView, Verify2FACodeView, CreateElectionView, EditElectionView, CreateGroupView, AllowGroupToVoteView, SearchUsersByName,\
      UpdateProfilePictureView, ListGroupsView, ListUsersInGroupView, EditPhoneNumberView, ChangePasswordView, UpdateAboutView, ProfileView, ElectionDetailView, CheckEligibilityView,\
      CastVoteView, AddCandidatesToElectionView, ElectionWinnerView, ActiveElectionsView, GetNonAdminUsersView, ElectionEditView, DeleteElectionView, CheckVotingStatusView,\
      InactiveElectionsView, ElectionResultView, Toggle2FAView, ToggleBiometricAuthView, ForgotPasswordWithOTPView, VerifyOTPView, ResetPasswordView, RequestAdminAccessView,\
      ApproveAdminAccessView, approve_success

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
    path('unverified/', UnverifiedPageView.as_view(), name='unverified_page'),
    path('resend-verification/', ResendVerificationEmailView.as_view(), name='resend_verification'),
    path('verify-2fa/', Verify2FACodeView.as_view(), name='verify2facode'),
    path('profile/biometric/',ToggleBiometricAuthView.as_view(),name='toggle_biometric'),
    path('profile/two-factor/',Toggle2FAView.as_view(),name='toggle_tfa'),
    path('forgot-password-with-otp/', ForgotPasswordWithOTPView.as_view(), name='forgot_password_with_otp'),
    path('verify-otp/', VerifyOTPView.as_view(), name='verify_otp'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset_password'),
    path('request-admin-access/',RequestAdminAccessView.as_view(), name='request_admin_access'),
    path('approve-admin-access/<token>/', ApproveAdminAccessView, name='approve_admin_access'),
    path('approve_success/', approve_success, name= 'approve_success'),
    # Election endpoints
    path('create-election/', CreateElectionView.as_view(), name='create_election'),
    path('delete-election/<election_id>/', DeleteElectionView.as_view(), name='delete_election'),
    path('edit-election/<uuid:election_id>/', EditElectionView.as_view(), name='edit_election'),
    path('election-edit/<election_id>/',ElectionEditView.as_view(),name='election_edit'),
    path('get-users/',GetNonAdminUsersView.as_view(), name='get_users'),
    # Group endpoints
    path('create-group/', CreateGroupView.as_view(), name='create_group'),
    path('list-group/', ListGroupsView.as_view(), name='list_group'),
    path('list-user-in-group/<group_id>/', ListUsersInGroupView.as_view(), name='list_user_in_group'),
    path('allow-group-to-vote/<election_id>/', AllowGroupToVoteView.as_view(), name='allow_group_to_vote'),
    path('add-candidate-to-election',AddCandidatesToElectionView.as_view(), name='add_candidate_to_election'),


    path('profile/phone-number/', EditPhoneNumberView.as_view(), name='edit_phone_number'),
    path('profile/change-password/', ChangePasswordView.as_view(), name='change_password'),
    path('profile/about/', UpdateAboutView.as_view(), name='update_about'),
    path('profile/', ProfileView.as_view(), name='profile_photo'),
    path('election-detail/<election_id>/', ElectionDetailView.as_view(), name='election_detail'),
    path('active-elections/', ActiveElectionsView.as_view(), name='active_elections'),

    path('check-eligibility/', CheckEligibilityView.as_view(), name='check_eligibility'),
    path('cast-vote/<election_id>/', CastVoteView.as_view(), name='cast_vote'),
    path('check-voting-status/<election_id>/', CheckVotingStatusView.as_view(),name='check_voting_status'),
    path('election-winner/<election_id>/', ElectionWinnerView.as_view(), name='election_winner'),
    path('voting-history/',InactiveElectionsView.as_view(), name='voting_history'),
    path('election-results/<election_id>/',ElectionResultView.as_view(), name='election_results'),
    # User search endpoint
    path('search-users/', SearchUsersByName.as_view(), name='search_users'),

    path('update-profile-picture/', UpdateProfilePictureView.as_view(), name='update_profile_picture'),
]