# Generated by Django 5.1.2 on 2024-11-27 20:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('myapp', '0013_remove_referendumvote_question_text_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='elections',
            name='icon',
            field=models.ImageField(blank=True, null=True, upload_to='election_icons'),
        ),
    ]
