from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from .serializers import (
    RegisterSerializer, UserLoginSerializer,
    ChangePasswordSerializer, ForgotPasswordSerializer,
    UserProfileSerializer, PublicUserProfileSerializer
)
from rest_framework.permissions import IsAuthenticated
from .models import User
from utils import Responder


class RegisterView(APIView):
    permission_classes = (AllowAny,)
    
    def _get_status_code(self, validated_data):

        return (
            101 if 'password' in validated_data else
            850 if validated_data.get('otp') else
            851
        )
    
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user_login_info = serializer.save()
        
        status_code = self._get_status_code(serializer.validated_data)
        return Responder.send(status_code, user_login_info)


class LoginView(APIView):
    permission_classes = (AllowAny,)
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        user_login_info = serializer.save()
        
        return Responder.send(110,user_login_info)
    
class LogoutView(APIView):
    def post(self, request):
        request.user.logout()
        return Responder.send(111)
    
class ChangePasswordView(APIView):
    permission_classes = (IsAuthenticated,)
    
    def post(self, request):
        serializer = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        result = serializer.save()
        
        return Responder.send(112, result)


class ForgotPasswordView(APIView):
    permission_classes = (AllowAny,)
    
    def _get_status_code(self, validated_data):
    
        return (
            113 if 'new_password' in validated_data else
            850 if validated_data.get('otp') and 'new_password' not in validated_data else
            851
        )
    
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        result = serializer.save()
        
        status_code = self._get_status_code(serializer.validated_data)
        return Responder.send(status_code, result)


class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserProfileSerializer(request.user)
        return Responder.send(code=114, data=serializer.data)
    def patch(self, request):
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Responder.send(115,serializer.data)

    def delete(self, request):
        request.user.delete()
        return Responder.send(116)



class PublicUserProfileView(APIView):

    permission_classes = (AllowAny,)
    
    def get(self, request, username):
    
        user = User.objects.get_by_username(username)
        
        if not user:
            return Responder.raise_error(118)
        
        serializer = PublicUserProfileSerializer(user)
        
        return Responder.send(131,serializer.data)
    
