# Generated by Django 5.1.2 on 2024-11-04 15:45

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0003_blacklistedtoken'),
    ]

    operations = [
        migrations.AddField(
            model_name='users',
            name='is_verified',
            field=models.BooleanField(default=False),
        ),
    ]
