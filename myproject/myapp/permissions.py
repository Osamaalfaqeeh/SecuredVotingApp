from rest_framework.permissions import BasePermission
from rest_framework_api_key.permissions import HasAPIKey

class IsAdmin(BasePermission):
    """
    Custom permission class to only allow admins to access the view.
    """

    def has_permission(self, request, view):
        # Check if the user is authenticated and if the role is 'admin'
        if request.user.is_authenticated and request.user.role.role_name == 'admin':
            return True
        return False

class IsAuthenticatedWithAPIKey(BasePermission):
    
    def has_permission(self, request, view):
        # Check if the request has a valid API key
        return HasAPIKey().has_permission(request, view)