from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from myapp.models import Users

class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        cutoff_date = timezone.now() - timedelta(hours=24)
        Users.objects.filter(is_verified=False, created_at__lt=cutoff_date).delete()
        self.stdout.write('Deleted unverified users')
