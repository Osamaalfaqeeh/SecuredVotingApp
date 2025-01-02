# Generated by Django 5.1.2 on 2024-12-31 22:52

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0027_adminaccessrequest'),
    ]

    operations = [
        migrations.AddField(
            model_name='elections',
            name='institution',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='elections', to='myapp.institutions'),
        ),
    ]
