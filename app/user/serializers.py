import re
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from rest_framework import serializers
from .models import User, RegistrationOtp
from .models import User
from django.core.mail import send_mail
from utils import (
    Responder,
    Generator)




class RegisterSerializer(serializers.Serializer):

    username = serializers.CharField(max_length=150, write_only=True, required=False)
    email = serializers.EmailField(write_only=True, required=True)
    phone = serializers.CharField(max_length=15, write_only=True, required=False)
    first_name = serializers.CharField(max_length=50, write_only=True, required=False)
    last_name = serializers.CharField(max_length=100, write_only=True, required=False)
    bio = serializers.CharField(max_length=500, write_only=True, required=False)
    
    password = serializers.CharField(max_length=128, write_only=True, required=False)
    confirm_password = serializers.CharField(max_length=128, write_only=True, required=False)
    otp = serializers.CharField(max_length=6, write_only=True, required=False)

    def validate(self, attrs):
        email = attrs['email']
        username = attrs.get('username')
        phone = attrs.get('phone', None)
        password = attrs.get('password')
        
        self._validate_existing_user(email, username, phone)
    
        if phone:
            self._validate_phone_number(phone)
        
        registration_otp = RegistrationOtp.objects.get_by_email(email)
        
        if 'otp' in attrs:
            # OTP verification step
            self._validate_otp(registration_otp, attrs['otp'])
        elif not password:
            # Initial registration - send OTP
            self._handle_initial_registration(attrs, email, registration_otp)
        
        if registration_otp and password:
            # Final registration step
            self._validate_password_confirmation(
                attrs['password'], attrs['confirm_password']
            )
        
        attrs['registration_otp'] = registration_otp
        return attrs

    def create(self, validated_data):
        registration_otp = validated_data['registration_otp']
        
        if not (registration_otp and 'password' in validated_data):
            return {}
        
        user = self._create_user_from_otp(registration_otp, validated_data)
        
        registration_otp.delete()
        return user.login('email')

    def _validate_existing_user(self, email, username, phone):
        if User.objects.filter(email=email).exists():
            Responder.raise_error(135)  # "Email exists"
        
        if username and User.objects.filter(username=username).exists():
            Responder.raise_error(134)  # "Username exists"
            
        if phone and User.objects.filter(phone=phone).exists():
            Responder.raise_error(136)  # "Phone number exists"

    def _validate_phone_number(self, phone):
        if phone and (re.match(r'^\+(1|91)\d+', phone)):
            return phone
        Responder.raise_error(137)  # "Invalid Indian phone number format"

    def _validate_otp(self, registration_otp, otp):
        """Validate OTP"""
        if not registration_otp or self._is_otp_expired(registration_otp.created_at):
            Responder.raise_error(117)  # "OTP expired or invalid"
        if registration_otp.otp != otp:
            Responder.raise_error(118)  # "Invalid OTP"

    def _handle_initial_registration(self, attrs, email, registration_otp):
        """Handle initial registration and send OTP"""
        otp = Generator.generate_otp()
        
        if registration_otp:
            RegistrationOtp.objects.handle_existing_otp(registration_otp, otp)
        else:
            RegistrationOtp.objects.create_new_otp(email, otp)
        
        self._send_otp_email(email, otp)

    def _validate_password_confirmation(self, password, confirm_password):
        if password != confirm_password:
            Responder.raise_error(154)

    def _create_user_from_otp(self, registration_otp, attrs):
        return User.objects.create_user(
            username=attrs.get('username', registration_otp.email.split('@')[0]),
            email=registration_otp.email,
            phone=attrs.get('phone'),
            password=attrs['password'],
            first_name=attrs.get('first_name', ''),
            last_name=attrs.get('last_name', ''),
            bio=attrs.get('bio', '')
        )

    def _is_otp_expired(self, created_at, minutes=5):
        expiry_time = created_at + timedelta(minutes=minutes)
        return timezone.now() > expiry_time

    def _send_otp_email(self, email, otp):
        subject = 'Your OTP Code'
        message = f'Your OTP is: {otp}'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]

        send_mail(subject, message, from_email, recipient_list)


class UserLoginSerializer(serializers.Serializer):

    identifier = serializers.CharField(write_only=True, required=True)
    password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        identifier = attrs.get('identifier')
        password = attrs.get('password')
        
        self._validate_required_fields(identifier, password)
        
        user = self._authenticate_user(identifier, password)
        
        attrs['user'] = user
        return attrs

    def create(self, validated_data):
        user = validated_data['user']
        return user.login('identifier')


    def _validate_required_fields(self, identifier, password):
        if not identifier:
            Responder.raise_error(151)
        if not password:
            Responder.raise_error(152)

    def _authenticate_user(self, identifier, password):
        user = User.objects.get_by_login_identifier(identifier, password)
        if not user:
            Responder.raise_error(102)
        return user


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True)
    new_password = serializers.CharField(write_only=True, required=True)
    confirm_password = serializers.CharField(write_only=True, required=True)

    def validate(self, attrs):
        old_password = attrs.get('old_password')
        new_password = attrs.get('new_password')
        confirm_password = attrs.get('confirm_password')
        
        user = self.context['request'].user
        if not user.check_password(old_password):
            Responder.raise_error(155)
        
        # Validate password confirmation
        if new_password != confirm_password:
            Responder.raise_error(154)
        
        attrs['user'] = user
        return attrs

    def create(self, validated_data):
        user = validated_data['user']
        user.set_password(validated_data['new_password'])
        user.save()
        return {'message': 'Password changed successfully'}


class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(write_only=True, required=True)
    otp = serializers.CharField(max_length=6, write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    def validate(self, attrs):
        email = attrs['email']
        
        user = User.objects.filter(email=email).first()
        if not user:
            Responder.raise_error(156)
        
        if 'otp' in attrs and 'new_password' in attrs:
            self._validate_password_reset(attrs, email)
        elif 'otp' in attrs:
            self._validate_otp(email, attrs['otp'])
        else:
            self._handle_otp_sending(email)
        
        attrs['user'] = user
        return attrs

    def create(self, validated_data):
        if 'new_password' in validated_data:
            user = validated_data['user']
            user.set_password(validated_data['new_password'])
            user.save()
            RegistrationOtp.objects.filter(email=user.email).delete()
            return {'message': 'Password reset successfully'}
        return {}

    def _handle_otp_sending(self, email):
        otp = Generator.generate_otp()
        registration_otp = RegistrationOtp.objects.get_by_email(email)
        
        if registration_otp:
            RegistrationOtp.objects.handle_existing_otp(registration_otp, otp)
        else:
            RegistrationOtp.objects.create_new_otp(email, otp)
        
        self._send_otp_email(email, otp)

    def _send_otp_email(self, email, otp):
        subject = 'Your Password Reset OTP'
        message = f'Your OTP code is: {otp}'
        from_email = settings.DEFAULT_FROM_EMAIL
        recipient_list = [email]
        send_mail(subject, message, from_email, recipient_list)

    def _validate_otp(self, email, otp):
        registration_otp = RegistrationOtp.objects.get_by_email(email)
        if not registration_otp or self._is_otp_expired(registration_otp.created_at):
            Responder.raise_error(117)
        if registration_otp.otp != otp:
            Responder.raise_error(118)

    def _validate_password_reset(self, attrs, email):
        self._validate_otp(email, attrs['otp'])
        if attrs['new_password'] != attrs['confirm_password']:
            Responder.raise_error(154)

    def _is_otp_expired(self, created_at, minutes=5):
        expiry_time = created_at + timedelta(minutes=minutes)
        return timezone.now() > expiry_time

class UserProfileSerializer(serializers.Serializer):
    id = serializers.IntegerField(read_only=True)
    username = serializers.CharField(read_only=True)
    email = serializers.EmailField(read_only=True)
    phone = serializers.CharField(read_only=True)
    first_name = serializers.CharField(required=False, allow_blank=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    full_name = serializers.SerializerMethodField()
    bio = serializers.CharField(required=False, allow_blank=True)
    profile_picture = serializers.URLField(required=False, allow_blank=True)
    date_joined = serializers.DateTimeField(read_only=True)
    last_login = serializers.DateTimeField(read_only=True)

    def get_full_name(self, user):
        return user.get_full_name()

    def update(self, user, validated_data):
        user.first_name = validated_data.get('first_name', user.first_name)
        user.last_name = validated_data.get('last_name', user.last_name)
        user.bio = validated_data.get('bio', user.bio)
        user.profile_picture = validated_data.get('profile_picture', user.profile_picture)
        user.save()
        return user

class PublicUserProfileSerializer(serializers.ModelSerializer):

    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            'id',
            'username',
            'full_name',
            'bio',
            'profile_picture',
            'date_joined'
        ]
        read_only_fields = fields

    def get_full_name(self, obj):
        return obj.get_full_name()