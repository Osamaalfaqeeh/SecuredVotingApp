from django.http import JsonResponse
from django.urls import reverse
from django.shortcuts import redirect

class EmailVerificationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Allow access to the unverified page and resend verification endpoints
        unverified_paths = [reverse('unverified_page'), reverse('resend_verification')]

        # Check if user is authenticated and email is verified
        if request.user.is_authenticated and not request.user.is_verified:
            # If user tries to access any page other than allowed, redirect them
            if request.path not in unverified_paths:
                return redirect('unverified_page')

        # Otherwise, continue processing the request
        response = self.get_response(request)
        return response