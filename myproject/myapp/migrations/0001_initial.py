# Generated by Django 5.1.2 on 2024-11-03 16:37

import django.db.models.deletion
import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Departments',
            fields=[
                ('department_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('department_name', models.CharField(max_length=100, unique=True)),
            ],
            options={
                'db_table': 'departments',
            },
        ),
        migrations.CreateModel(
            name='Institutions',
            fields=[
                ('institution_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('institution_name', models.CharField(max_length=255)),
                ('domain', models.CharField(max_length=255, unique=True)),
            ],
            options={
                'db_table': 'institutions',
            },
        ),
        migrations.CreateModel(
            name='Roles',
            fields=[
                ('role_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('role_name', models.CharField(max_length=50, unique=True)),
                ('permissions', models.JSONField(blank=True, null=True)),
            ],
            options={
                'db_table': 'roles',
            },
        ),
        migrations.CreateModel(
            name='Users',
            fields=[
                ('user_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('firstname', models.CharField(max_length=100)),
                ('lastname', models.CharField(max_length=100)),
                ('email', models.CharField(max_length=100, unique=True)),
                ('password_hash', models.CharField(max_length=255)),
                ('phone_number', models.CharField(blank=True, max_length=20, null=True)),
                ('bio', models.TextField(blank=True)),
                ('biometric_enabled', models.BooleanField(default=False)),
                ('notification_enabled', models.BooleanField(default=True)),
                ('profile_photo', models.CharField(blank=True, max_length=255, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('department', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.departments')),
                ('institution', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.institutions')),
                ('role', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.roles')),
            ],
            options={
                'db_table': 'users',
            },
        ),
        migrations.CreateModel(
            name='Logs',
            fields=[
                ('log_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('action', models.CharField(max_length=255)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('ip_address', models.CharField(blank=True, max_length=100, null=True)),
                ('status', models.CharField(blank=True, max_length=50, null=True)),
                ('error_message', models.TextField(blank=True, null=True)),
                ('additional_info', models.JSONField(blank=True, null=True)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
            ],
            options={
                'db_table': 'logs',
            },
        ),
        migrations.CreateModel(
            name='Elections',
            fields=[
                ('election_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('election_name', models.CharField(max_length=255)),
                ('description', models.TextField(blank=True)),
                ('start_time', models.DateTimeField()),
                ('end_time', models.DateTimeField()),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('icon', models.CharField(blank=True, max_length=255, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(db_column='created_by', null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
            ],
            options={
                'db_table': 'elections',
            },
        ),
        migrations.CreateModel(
            name='Authentication',
            fields=[
                ('auth_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('auth_type', models.CharField(blank=True, max_length=50, null=True)),
                ('auth_token', models.CharField(blank=True, max_length=255, null=True)),
                ('biometric_auth_token', models.CharField(blank=True, max_length=255, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(null=True)),
                ('user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
            ],
            options={
                'db_table': 'authentication',
            },
        ),
        migrations.CreateModel(
            name='Votes',
            fields=[
                ('vote_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('vote_token', models.CharField(max_length=255, unique=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('candidate', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
                ('election', models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.elections')),
            ],
            options={
                'db_table': 'votes',
            },
        ),
        migrations.CreateModel(
            name='VotingGroups',
            fields=[
                ('group_id', models.UUIDField(default=uuid.uuid4, editable=False, primary_key=True, serialize=False)),
                ('group_name', models.CharField(max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('created_by', models.ForeignKey(db_column='created_by', null=True, on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
            ],
            options={
                'db_table': 'voting_groups',
            },
        ),
        migrations.CreateModel(
            name='ElectionDepartments',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('department', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.departments')),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.elections')),
            ],
            options={
                'db_table': 'election_departments',
                'unique_together': {('election', 'department')},
            },
        ),
        migrations.CreateModel(
            name='ElectionGroups',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.elections')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
            ],
            options={
                'db_table': 'election_groups',
                'unique_together': {('user', 'election')},
            },
        ),
        migrations.CreateModel(
            name='Candidates',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.elections')),
                ('candidate', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
            ],
            options={
                'db_table': 'candidates',
                'unique_together': {('candidate', 'election')},
            },
        ),
        migrations.CreateModel(
            name='VotingGroupMembers',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.users')),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.votinggroups')),
            ],
            options={
                'db_table': 'voting_group_members',
                'unique_together': {('group', 'user')},
            },
        ),
        migrations.CreateModel(
            name='ElectionVotingGroups',
            fields=[
                ('id', models.AutoField(primary_key=True, serialize=False)),
                ('election', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.elections')),
                ('group', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='myapp.votinggroups')),
            ],
            options={
                'db_table': 'election_voting_groups',
                'unique_together': {('election', 'group')},
            },
        ),
    ]
