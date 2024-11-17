from .models import Logs
from django.utils.timezone import now

class LoggingMiddleware:
    """
    Middleware to log every incoming request and response.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = request.META.get('REMOTE_ADDR')
        user = request.user if request.user.is_authenticated else None

        # Log the request (pending)
        log_entry = Logs(
            user=user,
            action="Request received",
            ip_address=ip_address,
            status="Pending",
            timestamp=now(),
            additional_info={"method": request.method, "path": request.path}
        )
        log_entry.save()

        # Get the response
        response = self.get_response(request)

        # Log the response status
        log_entry.status = "Success" if response.status_code == 200 else "Failure"
        log_entry.save()

        return response
