from celery import shared_task
from datetime import timedelta
from django.utils.timezone import now
from myapp.models import Users, Roles
import logging


logger = logging.getLogger(__name__)

@shared_task
def manage_inactive_users():

    logger.info("Task started")
    admin_inactivity_threshold = now() - timedelta(days=180)
    normal_user_inactivity_threshold = now() - timedelta(days=90)

    # Fetch roles
    normal_user_role = Roles.objects.filter(role_name="user").first()
    admin_role = Roles.objects.filter(role_name="admin").first()

    if not normal_user_role or not admin_role:
        return "Required roles (Admin, Normal User) are not defined."

    # Downgrade inactive admins
    inactive_admins = Users.objects.filter(role=admin_role, last_login__lt=admin_inactivity_threshold)
    for admin in inactive_admins:
        admin.role = normal_user_role
        admin.save()

    # Reset password for inactive normal users
    inactive_normal_users = Users.objects.filter(role=normal_user_role, last_login__lt=normal_user_inactivity_threshold)
    for user in inactive_normal_users:
        user.is_active = False
        user.save()
    logger.info("Task completed")
    return "Inactive user management completed."
