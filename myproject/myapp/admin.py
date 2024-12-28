from django.utils import timezone
from django.contrib import admin
from .models import Request, SuperAdmin, Roles, AdminAccessRequest, Users
from django.core.mail import send_mail
from django.template.loader import render_to_string

# Register your models here.

class CustomAdminSite(admin.AdminSite):
    site_header = "Admin Dashboard"
    site_title = "Admin Dashboard"
    index_title = "Welcome to the Admin Panel"

# Register the custom admin site
admin_site = CustomAdminSite(name='custom_admin')


@admin.register(SuperAdmin)
class SuperAdminAdmin(admin.ModelAdmin):
    list_display = ('email', 'name', 'is_superuser')
    search_fields = ('email',)

@admin.register(Users)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ('firstname', 'lastname', 'phone_number', 'created_at', 'role', 'email', 'is_verified', 'is_active', 'last_login')
    list_filter = ('is_verified', 'is_active')
    search_fields = ('username', 'email')
    ordering = ('created_at',)
    readonly_fields = ('created_at','last_login','department')  # Make some fields read-only if needed

@admin.register(AdminAccessRequest)
class AdminAccessRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'created_at', 'approved', 'processed_at')
    actions = ['approve_requests', 'reject_requests']
    readonly_fields = ['processed_at']

    def approve_requests(self, request, queryset):
        for access_request in queryset.filter(approved=False):
            user = access_request.user
            # Assign admin role to the user
            admin_role = Roles.objects.get(role_name='admin')  # Replace with your role fetching logic
            user.role = admin_role
            user.save()
            access_request.approved = True
            access_request.processed_at = timezone.now()
            access_request.save()
            # Send a confirmation email
            email_message = render_to_string(
            'admin/admin_approval_confirmation.html',  # Email template
            {'user': user}  # Passing the user object to the email template
        )
            send_mail(
                'Admin Access Granted',
                email_message,
                'no-reply@yourdomain.com',
                [user.email],
                html_message= email_message,
                fail_silently=False,
            )
        self.message_user(request, "Selected requests have been approved.")
    approve_requests.short_description = "Approve selected requests"

admin_site.register(SuperAdmin, SuperAdminAdmin)
admin_site.register(Users, CustomUserAdmin)
admin_site.register(AdminAccessRequest, AdminAccessRequestAdmin)
    
