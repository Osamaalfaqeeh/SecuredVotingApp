# Generated by Django 5.1.2 on 2024-12-14 19:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0020_users_is_active'),
    ]

    operations = [
        migrations.AddField(
            model_name='users',
            name='deleted',
            field=models.BooleanField(default=False),
        ),
    ]
