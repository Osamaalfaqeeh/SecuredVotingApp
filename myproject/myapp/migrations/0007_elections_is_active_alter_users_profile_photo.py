# Generated by Django 5.1.2 on 2024-11-11 11:59

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0006_authentication_is_active_users_is_2fa_enabled'),
    ]

    operations = [
        migrations.AddField(
            model_name='elections',
            name='is_active',
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name='users',
            name='profile_photo',
            field=models.ImageField(blank=True, null=True, upload_to='profile_pics'),
        ),
    ]
