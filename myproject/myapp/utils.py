from django.core import signing
import time
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.core.cache import cache
import secrets
import hashlib
# from django.core.mail import send_mail
# from django.conf import settings

TOKEN_EXPIRATION_TIME = 86400

def generate_verification_token(user_id):
    data = {
        "user_id": str(user_id),
        "timestamp": int(time.time())  # Add a timestamp
    }
    return signing.dumps(data, salt="email-verification-salt")

def verify_token(token, max_age=TOKEN_EXPIRATION_TIME):
    try:
        data = signing.loads(token, salt="email-verification-salt", max_age=max_age)
        return data["user_id"]
    except signing.SignatureExpired:
        return None
    except signing.BadSignature:
        return None


def generate_2fa_code():
    """Generate a cryptographically secure 6-digit code for 2FA."""
    return str(secrets.randbelow(1000000)).zfill(6)  # Ensures a 6-digit code

def send_2fa_code(user):
    """Send the 2FA code to the user's email in HTML format."""
    code = generate_2fa_code()
    
    # Store the code in cache with a key based on the user ID and a 5-minute timeout
    cache.set(f"2fa_code_{user.user_id}", code, timeout=300)  # 5 minutes = 300 seconds
    
    # Render HTML email content
    subject = "Your Two-Factor Authentication Code"
    message = render_to_string('login/2fa_email.html', {'user': user, 'code': code})
    
    email = EmailMessage(
        subject,
        message,
        'noreply@example.com',  # From email address
        [user.email],           # To email address
    )
    email.content_subtype = "html"  # Ensures the email is sent as HTML
    email.send()

def generate_anonymous_id(user_id, election_id, position_id):
    """
    Generate an anonymous ID for a user in a specific election using the user ID and election ID.
    This ensures that the anonymous ID is stable for the same user and election.
    """
    # Combine user ID and election ID into a string
    combined_data = f"{user_id}-{election_id}-{position_id}"

    # Hash the combined data to create a unique, irreversible anonymous ID
    anonymous_id = hashlib.sha256(combined_data.encode()).hexdigest()

    return anonymous_id

def get_client_ip(request):
        """Return the client's IP address."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip