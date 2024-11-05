from django.core import signing
import time
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

# def send_verification_email(user):
#     token = generate_verification_token(user.user_id)
#     verification_link = f"{settings.FRONTEND_URL}/verify-email/{token}"
#     subject = "Email Verification"
#     message = f"Please click the following link to verify your email: {verification_link}"
    
#     send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [user.email], fail_silently=False)