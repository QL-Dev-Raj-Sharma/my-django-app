import jwt
import time
from django.utils import timezone
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager
from django.db.models import Q
from django.utils.timezone import now
from django.conf import settings
from utils import Responder


class RegistrationOtpManager(models.Manager):
    def get_by_email(self, email):
        return self.filter(email=email).first()
    
    
    def create_new_otp(self, email, otp):
        today = now().replace(hour=0, minute=0, second=0, microsecond=0)
        otps = self.filter(email=email, created_at__gte=today).order_by('-created_at')

        if otps.count() >= 5:
            Responder.raise_error(801)

        latest_otp = otps.first()
        if latest_otp and (now() - latest_otp.created_at).total_seconds() < 60:
            Responder.raise_error(802)

        if latest_otp:
            return self.handle_existing_otp(latest_otp, otp)
        return self.create(email=email, otp=otp)
    
    def handle_existing_otp(self, registration_otp, new_otp):
        registration_otp.otp = new_otp
        registration_otp.created_at = timezone.now()
        registration_otp.save(update_fields=['otp', 'created_at'])
        return registration_otp


class RegistrationOtp(models.Model):
    email = models.EmailField()
    otp = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    
    objects = RegistrationOtpManager()
    
    class Meta:
        db_table = 'registration_otp'
    
    def __str__(self):
        return f"OTP for {self.email}"


class UserManager(BaseUserManager):

    def get_by_email(self, email):
        return self.filter(email=email).first()
    
    def create_user(self, username, email, phone=None, password=None, **extra_fields):
        if not username:
            Responder.raise_error(701)
        if not email:
            Responder.raise_error(702)

        email = self.normalize_email(email)
        user = self.model(username=username, email=email, phone=phone, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def get_by_login_identifier(self, identifier, password):
        user = self.filter(
            Q(username=identifier) | Q(email=identifier)).first()
        
        return user if user and user.check_password(password) else None
    
    def get_by_username(self, username):
        return self.filter(username=username).first()



class User(AbstractBaseUser):
    username = models.CharField(max_length=20, unique=True)
    email = models.EmailField(max_length=100, unique=True)
    password = models.CharField(max_length=128)
    last_login = models.DateTimeField(null=True, blank=True)

    access_token_created_at = models.IntegerField(null=True)
    phone = models.CharField(max_length=15, blank=True, null=True, unique=True)
    first_name = models.CharField(max_length=30, blank=True)
    last_name = models.CharField(max_length=30, blank=True)
    bio = models.TextField(max_length=500, blank=True)
    profile_picture = models.ImageField(upload_to="profile_pics/", blank=True, null=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email']
    
    def __str__(self):
        return self.username
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()
    
    def create_access_token(self):
        self.access_token_created_at = int(time.time())
        self.save(update_fields=['access_token_created_at'])
        
        payload = {
            'user_id': self.id,
            'username': self.username,
            'iat': self.access_token_created_at,
            'exp': self.access_token_created_at + 3600 * 24
        }
        
        token = jwt.encode(
            payload,
            settings.SECRET_KEY,
            algorithm='HS256'
        )
        
        return token.decode('utf-8') if isinstance(token, bytes) else token

    def login(self, method='username'):
        self.last_login = timezone.now()
        self.save(update_fields=['last_login'])
        
        access_token = self.create_access_token()
        
        return {
            'user_id': self.id,
            'username': self.username,
            'email': self.email,
            'login_method': method,
            'access_token': access_token
        }
    
    def logout(self):
        return self.update({'access_token_created_at': None})
    
    def get_profile_data(self):

        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'phone': self.phone,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.get_full_name(),
            'bio': self.bio,
            'profile_picture': self.profile_picture,
            'date_joined': self.date_joined,
            'last_login': self.last_login
        }

    def get_public_profile_data(self):
    
        return {
            'id': self.id,
            'username': self.username,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'full_name': self.get_full_name(),
            'bio': self.bio,
            'profile_picture': self.profile_picture,
            'date_joined': self.date_joined
        }
