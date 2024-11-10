# Generated by Django 5.1.2 on 2024-11-08 22:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0005_users_last_login'),
    ]

    operations = [
        migrations.AddField(
            model_name='authentication',
            name='is_active',
            field=models.BooleanField(default=True),
        ),
        migrations.AddField(
            model_name='users',
            name='is_2fa_enabled',
            field=models.BooleanField(default=False),
        ),
    ]
