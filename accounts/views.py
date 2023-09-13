from rest_framework.response import Response
from .serializers import UserSerializer
from rest_framework.decorators import action
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication, SessionAuthentication,BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import viewsets, status
from django.contrib.auth import authenticate,logout,login
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .serializers import ChangePasswordSerializer,EmailResetPassword,ResetPassword
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from rest_framework.authtoken.models import Token
from .models import UserAccount
from .tokens import account_activation_token 
from django.utils.encoding import force_str
from django.contrib import messages
from django.core.mail import send_mail 
from django.conf import settings
from Crypto.Cipher import AES
import base64
import hashlib
import time,random
import os
from django.contrib.sessions.models import Session
import uuid
from django.contrib.auth import update_session_auth_hash

class Function_Email:

    def __init__(self):
        self.secret_key = os.urandom(32)

    def encode_email(self,email):
        hex_email = ""
        for char in email:
            hex_char = hex(ord(char))[2:]
            hex_email += hex_char
        return hex_email
    
    def decode_email(self,hex_email):
        email = ""
        hex_pairs = [hex_email[i:i+2] for i in range(0, len(hex_email), 2)]
        for hex_pair in hex_pairs:
            char = chr(int(hex_pair, 16))
            email += char
        return email

    def resetpassword_via_Email(self,request,to_email):
        subject = "Confirm to Reset Password"
        message = message = render_to_string("static/reset_password.html", {
            'domain': get_current_site(request).domain,
            'encrypt_email': self.encode_email(to_email),
            'protocol': 'https' if request.is_secure() else 'http'
        })
        encrypt_email = self.encode_email(to_email)
        print(encrypt_email)
        from_email = settings.EMAIL_HOST
        send_mail(subject,message,from_email,[to_email])

    def Activate_Email(self,request, user, to_email):
        data = {}
        mail_subject = "Activate your user account."
        message = render_to_string("static/verify_email.html", {
            'user': user.username,
            'domain': get_current_site(request).domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
            "protocol": 'https' if request.is_secure() else 'http'
        })
        email = EmailMessage(mail_subject, message, to=[to_email])
        if email.send():
            messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
                    received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
            data['response'] = 'Your account is activated. Now you can login into your accounts'
        else:
            messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')
            data['response'] = 'Can not active your account'
        return Response(data)
    
    def encrypt_token(self, token):
        block_size = AES.block_size
        cipher = AES.new(self.secret_key, AES.MODE_CBC, os.urandom(16))
        token = token + ' ' * (block_size - len(token) % block_size)
        encrypted_token = cipher.encrypt(token.encode('utf-8'))
        return base64.b32encode(encrypted_token).decode('utf-8')

    def generate_otp(self, encrypted_token, timestamp):
        random_number = random.randint(100000, 999999)
        data_to_hash = f'{encrypted_token}{timestamp}{random_number}'.encode('utf-8')
        sha1_hash = hashlib.sha1(data_to_hash).hexdigest()
        offset = int(sha1_hash[-1], 16)
        truncated_hash = sha1_hash[offset * 2 : offset * 2 + 8]
        otp = int(truncated_hash, 16) % 10**6
        return f'{otp:06}'

    def Activate_Email_by_OTP(self,request,to_email):
        mail_subject = "Verify your account."
        timestamp = int(time.time())
        try:
            user = UserAccount.objects.get(email=to_email)
            token = Token.objects.get(user=user)
            user_token = str(token)
        except UserAccount.DoesNotExist:
            return Response({'message':'Account do not exist'})
        except Token.DoesNotExist:
            return Response({'message':'Token do not exist'})
        encrypted_token = self.encrypt_token(user_token)
        otp = self.generate_otp(encrypted_token, timestamp)
        message = f'Your otp is :{otp}, now you can get otp to reset password'
        email = EmailMessage(mail_subject, message, to=[to_email])
        if email.send():
            user.is_otp = otp
            user.save()
            messages.success(request, f'Dear <b>{user}</b>, please go to you email <b>{to_email}</b> inbox and click on \
                    received activation link to confirm and complete the registration. <b>Note:</b> Check your spam folder.')
        else:
            messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')


@api_view(['GET'])
def verify_email_api(request, uidb64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = UserAccount.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, UserAccount.DoesNotExist):
        user = None

    if user is not None and account_activation_token.check_token(user, token):
        user.activate_account()
        return Response({'message': 'Email verified successfully. You can now log in.'}, status=status.HTTP_200_OK)
    else:
        return Response({'message': 'Invalid email verification link.'}, status=status.HTTP_400_BAD_REQUEST)

class EmailVerificationView(viewsets.ViewSet):
    @action(detail=False, methods=['get'])
    def verify_email(self,request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = UserAccount.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserAccount.DoesNotExist):
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.activate_account()
            return Response({'message': 'Email verified successfully. You can now log in.'}, status=status.HTTP_200_OK)
        else:
            return Response({'message': 'Invalid email verification link.'}, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post']) 
    def link_resetpassword_email(self, request, encryptemail):
        serializer = ResetPassword(data=self.request.data)
        if serializer.is_valid():
            try:
                decode_email = Function_Email()
                email = decode_email.decode_email(encryptemail)
                user = UserAccount.objects.get(email=email)
            except (TypeError, ValueError, OverflowError, UserAccount.DoesNotExist):
                user = None
            new_password = serializer.validated_data.get('new_password')
            re_new_password = serializer.validated_data.get('re_new_password')
            if not re_new_password or not new_password:
                return Response({'message': 'Vui lòng điền đầy đủ thông tin'}, status=status.HTTP_400_BAD_REQUEST)
            if new_password != re_new_password:
                return Response({'message': 'Mật khẩu xác nhận không khớp'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(self.request, user)
            return Response({'message': 'Thay đổi mật khẩu thành công'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class UserViewSet(viewsets.ViewSet):
    @action(detail=False, methods=['post'])
    def signup(self, request):
        serializer = UserSerializer(data=request.data)
        data = {}
        if serializer.is_valid():
            user = serializer.save()
            to_email = user.email
            try:
                function_email = Function_Email()
                function_email.Activate_Email(request, user, to_email)
                data['response'] = 'User registered successfully. Please check your email for verification.'
                data['email'] = to_email
                data['username'] = user.username
                if Token.objects.filter(user=user).exists():
                    token = Token.objects.get(user=user)
                else:
                    token = Token.objects.create(user=user)
                data['token'] = token.key
                data['email_sent'] = True 
            except Exception as e:
                data['response_error'] = f'Error sending email: {str(e)}'
                data['email_sent'] = False  
        else:
            data = serializer.errors
            data['email_sent'] = False 

        return Response(data, status=status.HTTP_400_BAD_REQUEST)

    def signup_backup(self, request):
        serializer = UserSerializer(data=request.data)
        data={}
        if serializer.is_valid():
            user = serializer.save()
            data['response']='User registered successfully'
            data['email'] = user.email
            data['username']= user.username
            if Token.objects.filter(user=user).exists():
                token = Token.objects.get(user=user)
            else :
                token = Token.objects.create(user=user)
            data['token'] = token.key
        else :
            data=serializer.errors
        return Response(data, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = authenticate(request,email=email, password=password)
        if user is not None:
            login(request,user)
            token, _ = Token.objects.get_or_create(user=user)
            return Response({'message':'login success' ,'token': token.key})
        else:
            return Response({'error': 'Login Fail'}, status=status.HTTP_401_UNAUTHORIZED)
        
    @action(detail=False, methods=['post'])
    def logout(self, request):
        if request.user.is_authenticated:
            logout(request)
            return Response({'message': 'Logout successful'})
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

class SetViews(APIView):
    authentication_classes = [BasicAuthentication,SessionAuthentication]
    permission_classes =[IsAuthenticated]
    def test_token_api(self, request):
        user = request.user
        return Response({'message': f'{user.username} is allowed to do this work with {user.email}'})
    def get(self, request):
        return self.test_token_api(request)
    def post(self, request):
        return self.test_token_api(request)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password_api(request):
    if request.method == 'POST':
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if not user.check_password(serializer.data.get('old_password')):
                return Response({'message': 'Mật khẩu cũ không chính xác'}, status=status.HTTP_400_BAD_REQUEST)
            if serializer.data.get('new_password') != serializer.data.get('re_new_password'):
                return Response({'message': 'Mật khẩu xác nhận không khớp'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(serializer.data.get('new_password'))
            user.save()
            update_session_auth_hash(request, user) 
            return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class Function_password(viewsets.ViewSet):
    
    @action(detail=False, methods=['post'])   
    def reset_password(self,request):
        serializer = EmailResetPassword(data=request.data)
        data={}
        if serializer.is_valid():
            to_email =  serializer.validated_data.get('email')
            if not to_email:
                data['Response'] = 'You need Email to Reset password'
            try:
                function_email = Function_Email()
                function_email.resetpassword_via_Email(request,to_email)
                data['Response'] = "Succsesfully, please check email to reset password"
                data['send_email'] = True
            except Exception as e:
                data['response_error'] = f'Error sending email: {str(e)}' 
                data['send_email'] = False 
        else:
            data = serializer.errors
            data['email_sent'] = False 
        return Response(data, status=status.HTTP_400_BAD_REQUEST)
    
    # permission_classes = (IsAuthenticated)
    @action(detail=False, methods=['post'])
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data.get('old_password')
            new_password = serializer.validated_data.get('new_password')
            re_new_password = serializer.validated_data.get('re_new_password')
            if not old_password or not new_password or not re_new_password:
                return Response({'message': 'Vui lòng điền đầy đủ thông tin'}, status=status.HTTP_400_BAD_REQUEST)
            if not user.check_password(old_password):
                return Response({'message': 'Mật khẩu cũ không chính xác'}, status=status.HTTP_400_BAD_REQUEST)
            if new_password != re_new_password:
                return Response({'message': 'Mật khẩu xác nhận không khớp'}, status=status.HTTP_400_BAD_REQUEST)
            user.set_password(new_password)
            user.save()
            update_session_auth_hash(request, user)
            return Response({'message': 'Thay đổi mật khẩu thành công'}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
