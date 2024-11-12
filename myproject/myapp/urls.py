from django.urls import path
from .views import LoginView, RegisterView, LogoutView, CustomTokenRefreshView, ExampleView, activate, activation_success, activation_failed, already_verified,\
      UnverifiedPageView, ResendVerificationEmailView, Verify2FACodeView, CreateElectionView, EditElectionView, CreateGroupView, AllowGroupToVoteView, SearchUsersByName,\
      UpdateProfilePictureView, ListGroupsView, ListUsersInGroupView

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

    # Election endpoints
    path('create-election/', CreateElectionView.as_view(), name='create_election'),
    path('edit-election/<uuid:election_id>/', EditElectionView.as_view(), name='edit_election'),

    # Group endpoints
    path('create-group/', CreateGroupView.as_view(), name='create_group'),
    path('list-group/', ListGroupsView.as_view(), name='list_group'),
    path('list-user-in-group/<group_id>/', ListUsersInGroupView.as_view(), name='list_user_in_group'),
    path('allow-group-to-vote/<uuid:election_id>/', AllowGroupToVoteView.as_view(), name='allow_group_to_vote'),

    # User search endpoint
    path('search-users/', SearchUsersByName.as_view(), name='search_users'),

    path('update-profile-picture/', UpdateProfilePictureView.as_view(), name='update_profile_picture'),
]