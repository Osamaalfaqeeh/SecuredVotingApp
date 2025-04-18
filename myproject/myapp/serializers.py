# serializers.py
from rest_framework import serializers
from .models import Users, Authentication, Institutions, Elections, ReferendumOption, ReferendumQuestion, Roles, Request
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime, timedelta
from django.core.validators import validate_email
from django.utils.timezone import make_aware, is_naive

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    firstname = serializers.CharField(max_length=100)
    lastname = serializers.CharField(max_length=100)
    phone_number = serializers.CharField(max_length=15, required=False)

    def validate_email(self, value):
        # Check if the email already exists
        try:
            validate_email(value)
        except serializers.ValidationError:
            raise serializers.ValidationError("Invalid email format.")
        
        existing_user = Users.objects.filter(email=value).first()
        if existing_user:
            if existing_user.deleted:
                self.context['existing_user'] = existing_user  # Pass the user to the create method
            else:
                raise serializers.ValidationError("A user with this email already exists.")

        # Extract the domain and check if it belongs to any known institution
        domain = value.split('@')[-1]
        institution = None
        for inst in Institutions.objects.all():
            if domain.endswith(inst.domain):  # Check if the email domain includes the institution's domain
                institution = inst
                break

        if not institution:
            raise serializers.ValidationError("Only educational institution emails are allowed.")
        
        self.institution = institution  # Store the institution for use in create()
        return value

    def create(self, validated_data):
        # Determine role based on the subdomain
        email = validated_data['email']
        # role = 'student' if email.startswith("std.") else 'instructor'
        role = Roles.objects.get(role_name = 'user')

        existing_user = self.context.get('existing_user')
        if existing_user:
            # Update the existing user's data
            existing_user.password_hash = make_password(validated_data['password'])
            existing_user.firstname = validated_data['firstname']
            existing_user.lastname = validated_data['lastname']
            existing_user.phone_number = validated_data.get('phone_number')
            existing_user.institution = self.institution
            existing_user.deleted = False  # Reactivate the user
            existing_user.is_active = True
            existing_user.save()
            return existing_user

        # Create user with the specified data and institution
        user = Users.objects.create(
            email=email,
            password_hash=make_password(validated_data['password']),
            firstname=validated_data['firstname'],
            lastname=validated_data['lastname'],
            phone_number=validated_data.get('phone_number'),
            institution=self.institution,  # Assign institution based on domain
            role = role,
            # role=role  # Assign role based on subdomain
        )

        # Create an initial entry in the Authentication table if needed
        Authentication.objects.create(
            user=user,
            auth_type='JWT',  # Specify auth type
            auth_token='initial_registration',
            created_at=datetime.now()
        )

        
        return user
    

class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        email = data.get("email")
        password = data.get("password")

        try:
            user = Users.objects.get(email=email, deleted = False)
        except Users.DoesNotExist:
            raise serializers.ValidationError("Invalid email or password.")

        # Check if the provided password matches the stored password hash
        if not check_password(password, user.password_hash):
            raise serializers.ValidationError("Invalid email or password.")

        # Generate JWT tokens for the authenticated user
        refresh = RefreshToken.for_user(user)
        data['refresh'] = str(refresh)
        data['access'] = str(refresh.access_token)
        data['user_id'] = user.user_id
        data['user'] = user
        return data
    

class ReferendumOptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReferendumOption
        fields = ['id', 'option_text']

class ReferendumQuestionSerializer(serializers.ModelSerializer):
    options = ReferendumOptionSerializer(many=True,write_only =True)

    class Meta:
        model = ReferendumQuestion
        fields = ['id', 'question_text', 'is_mandatory', 'options']

class ElectionSerializer(serializers.ModelSerializer):
    referendum_questions = ReferendumQuestionSerializer(many=True, read_only=True)
    allow_self_vote = serializers.BooleanField(default=False, write_only=True)
    class Meta:
        model = Elections
        fields = ['election_name', 'description', 'start_time', 'end_time', 'is_active', 'icon','allow_self_vote', 'referendum_questions']

    def validate(self, data):
        if data['start_time'] >= data['end_time']:
            raise serializers.ValidationError("End date must be after start date.")
        if is_naive(data['start_time']):
            data['start_time'] = make_aware(data['start_time'])

        if is_naive(data['end_time']):
            data['end_time'] = make_aware(data['end_time'])
        return data
    

class ProfilePictureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Users
        fields = ['profile_photo']

class RequestSerializer(serializers.ModelSerializer):
    user_name = serializers.SerializerMethodField()
    election_name = serializers.SerializerMethodField()
    position_name = serializers.SerializerMethodField()

    class Meta:
        model = Request
        fields = ['id', 'user', 'user_name', 'request_type', 'status', 'created_at', 'updated_at', 'election', 'election_name', 'position', 'position_name']
    
    def get_user_name(self, obj):
        return obj.user.firstname + " " + obj.user.lastname  # Adjust based on your Users model

    def get_election_name(self, obj):
        return obj.election.election_name if obj.election else None
    
    def get_position_name(self, obj):
        return obj.position.position_name if obj.position else None

# class GroupSerializer(serializers.ModelSerializer):
#     # class Meta:
#     #     model = Group
#     #     fields = ['name', 'election']