import jwt
import time
from rest_framework.authentication import BaseAuthentication
from django.conf import settings
from rest_framework import exceptions
from app.user.models import User
from utils import Responder

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
                Responder.raise_error(901)
                
            
            if payload['exp'] < int(time.time()):
                Responder.raise_error(902)
                
            user = User.objects.get(pk=payload['user_id'])
            
        
            if user.access_token_created_at != payload['iat']:
                Responder.raise_error(903)
                
            return (user, None)
            
        except jwt.ExpiredSignatureError:
            Responder.raise_error(904)
        except (jwt.InvalidTokenError, User.DoesNotExist):
            Responder.raise_error(905)