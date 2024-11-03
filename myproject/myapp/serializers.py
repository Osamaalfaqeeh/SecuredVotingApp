# serializers.py
from rest_framework import serializers
from .models import Users, Authentication, Institutions
from django.contrib.auth.hashers import make_password, check_password
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime, timedelta

class RegisterSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    firstname = serializers.CharField(max_length=100)
    lastname = serializers.CharField(max_length=100)
    phone_number = serializers.CharField(max_length=20, required=False)

    def validate_email(self, value):
        # Check if the email already exists
        if Users.objects.filter(email=value).exists():
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

        # Create user with the specified data and institution
        user = Users.objects.create(
            email=email,
            password_hash=make_password(validated_data['password']),
            firstname=validated_data['firstname'],
            lastname=validated_data['lastname'],
            phone_number=validated_data.get('phone_number'),
            institution=self.institution,  # Assign institution based on domain
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
            user = Users.objects.get(email=email)
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