from django.db import models
import uuid
from datetime import datetime

class Authentication(models.Model):
    auth_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('Users', models.CASCADE, null=True)  # Foreign key is often nullable
    auth_type = models.CharField(max_length=50, blank=True, null=True)  # Optional field
    auth_token = models.CharField(max_length=512, blank=True, null=True)  # Optional field
    biometric_auth_token = models.CharField(max_length=255, blank=True, null=True)  # Optional field
    created_at = models.DateTimeField(auto_now_add=True)  # Timestamp fields usually don’t need null=True
    expires_at = models.DateTimeField(null=True)  # Nullable in case there's no expiration set
    is_active = models.BooleanField(default=True)

    def is_expired(self):
            return datetime.now() >= self.expires_at

    class Meta:
        db_table = 'authentication'


class Candidates(models.Model):
    id = models.AutoField(primary_key=True)
    candidate = models.ForeignKey('Users', models.CASCADE)
    election = models.ForeignKey('Elections', models.CASCADE)

    class Meta:
        db_table = 'candidates'
        unique_together = (('candidate', 'election'),)


class Departments(models.Model):
    department_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    department_name = models.CharField(unique=True, max_length=100)

    class Meta:
        db_table = 'departments'


class ElectionDepartments(models.Model):
    id = models.AutoField(primary_key=True)
    election = models.ForeignKey('Elections', models.CASCADE)
    department = models.ForeignKey(Departments, models.CASCADE)

    class Meta:
        db_table = 'election_departments'
        unique_together = (('election', 'department'),)


class ElectionGroups(models.Model):
    id = models.AutoField(primary_key=True)
    user = models.ForeignKey('Users', models.CASCADE)
    election = models.ForeignKey('Elections', models.CASCADE)

    class Meta:
        db_table = 'election_groups'
        unique_together = (('user', 'election'),)


class ElectionVotingGroups(models.Model):
    id = models.AutoField(primary_key=True)
    election = models.ForeignKey('Elections', models.CASCADE)
    group = models.ForeignKey('VotingGroups', models.CASCADE)

    class Meta:
        db_table = 'election_voting_groups'
        unique_together = (('election', 'group'),)


class Elections(models.Model):
    election_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    election_name = models.CharField(max_length=255)
    description = models.TextField(blank=True)  # Allow blank descriptions
    start_time = models.DateTimeField()
    end_time = models.DateTimeField()
    created_by = models.ForeignKey('Users', models.CASCADE, db_column='created_by', null=True)  # Foreign key can be nullable
    updated_at = models.DateTimeField(auto_now=True)
    icon = models.CharField(max_length=255, blank=True, null=True)  # Optional field
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'elections'


class Institutions(models.Model):
    institution_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    institution_name = models.CharField(max_length=255)
    domain = models.CharField(unique=True, max_length=255)

    class Meta:
        db_table = 'institutions'


class Logs(models.Model):
    log_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey('Users', models.CASCADE, null=True)  # Nullable in case of system logs not linked to a user
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.CharField(max_length=100, blank=True, null=True)  # Optional field
    status = models.CharField(max_length=50, blank=True, null=True)  # Optional field
    error_message = models.TextField(blank=True, null=True)  # Optional field
    additional_info = models.JSONField(blank=True, null=True)  # Optional field

    class Meta:
        db_table = 'logs'


class Roles(models.Model):
    role_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    role_name = models.CharField(unique=True, max_length=50)
    permissions = models.JSONField(blank=True, null=True)  # Optional field

    class Meta:
        db_table = 'roles'


class Users(models.Model):
    user_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    firstname = models.CharField(max_length=100)
    lastname = models.CharField(max_length=100)
    email = models.CharField(unique=True, max_length=100)
    password_hash = models.CharField(max_length=255)
    phone_number = models.CharField(max_length=20, blank=True, null=True)  # Optional contact info
    bio = models.TextField(blank=True)  # Allow blank bios
    biometric_enabled = models.BooleanField(default=False)
    notification_enabled = models.BooleanField(default=True)
    profile_photo = models.CharField(max_length=255, blank=True, null=True)  # Optional profile photo
    department = models.ForeignKey(Departments, models.CASCADE, null=True)  # Nullable foreign key
    role = models.ForeignKey(Roles, models.CASCADE, null=True)  # Nullable foreign key
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    institution = models.ForeignKey(Institutions, models.CASCADE, null=True)  # Nullable foreign key
    is_verified = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    is_2fa_enabled = models.BooleanField(default=False)

    @staticmethod
    def get_email_field_name():
        return 'email'
    
    @property
    def is_authenticated(self):
        # Return True if the user is considered authenticated
        return True

    class Meta:
        db_table = 'users'


class Votes(models.Model):
    vote_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    election = models.ForeignKey(Elections, models.CASCADE, null=True)  # Nullable if the election is deleted
    candidate = models.ForeignKey(Users, models.CASCADE, null=True)  # Nullable if the candidate is deleted
    vote_token = models.CharField(unique=True, max_length=255)
    timestamp = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'votes'


class VotingGroupMembers(models.Model):
    id = models.AutoField(primary_key=True)
    group = models.ForeignKey('VotingGroups', models.CASCADE)
    user = models.ForeignKey(Users, models.CASCADE)

    class Meta:
        db_table = 'voting_group_members'
        unique_together = (('group', 'user'),)


class VotingGroups(models.Model):
    group_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    group_name = models.CharField(max_length=255)
    created_by = models.ForeignKey(Users, models.CASCADE, db_column='created_by', null=True)  # Nullable if creator is deleted
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'voting_groups'


class BlacklistedToken(models.Model):
    token = models.CharField(max_length=512)
    blacklisted_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'blacklistedToken'
    # class Meta:
    #     constraints = [
    #         models.UniqueConstraint(fields=['token'], name='unique_blacklisted_token', condition=models.Q(token__length=512))  # Ensures unique tokens
    #     ]