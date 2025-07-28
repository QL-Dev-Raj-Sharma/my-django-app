import jwt
import time
from rest_framework.authentication import BaseAuthentication
from django.conf import settings
from rest_framework import exceptions
from app.user.models import User

class UserTokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return None
            
        try:
            token = auth_header.split(' ')[1]
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            
    
            required_claims = ['user_id', 'iat', 'exp']
            if not all(claim in payload for claim in required_claims):
                raise exceptions.AuthenticationFailed('Invalid token claims')
                
            
            if payload['exp'] < int(time.time()):
                raise exceptions.AuthenticationFailed('Token has expired')
                
            user = User.objects.get(pk=payload['user_id'])
            
        
            if user.access_token_created_at != payload['iat']:
                raise exceptions.AuthenticationFailed('Token invalidated')
                
            return (user, None)
            
        except jwt.ExpiredSignatureError:
            raise exceptions.AuthenticationFailed('Token has expired')
        except (jwt.InvalidTokenError, User.DoesNotExist):
            raise exceptions.AuthenticationFailed('Invalid token')