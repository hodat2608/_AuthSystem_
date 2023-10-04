from .models import UserAccount
from rest_framework import viewsets, status
from django.contrib.auth import authenticate,logout,login
from rest_framework.views import APIView
from rest_framework.authentication import TokenAuthentication, SessionAuthentication,BasicAuthentication
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes
from django.template.loader import render_to_string
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.authtoken.models import Token
from .models import UserAccount
from .serializers import UserSerializer,CreateAccountUser
from .tokens import account_activation_token 
from django.utils.encoding import force_str
from django.contrib import messages
from django.conf import settings
from django.core.mail import send_mail
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import update_session_auth_hash
from .serializers import ChangePasswordSerializer,ResetPasswordEmailSerializer
from Crypto.Cipher import AES
from .serializers import UidAndTokenSerializer,Email_password,TokenCreateSerializer
import base64
from django.contrib.auth.tokens import default_token_generator
import hashlib
import time,random
import os
from django.contrib.sessions.models import Session
from djoser import signals, utils
from django.contrib.auth import login, logout
from accounts.combat import get_user_email
class FunctionView():

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
        subject = "Reset Password"
        try:
            message = render_to_string("static/password_reset_email.html", {
                'domain': get_current_site(request).domain,
                'encrypt_email': self.encode_email(to_email),
                'protocol': 'https' if request.is_secure() else 'http'
            })
        except:
            pass
        encrypt_email = self.encode_email(to_email)
        print(encrypt_email)
        from_email = settings.EMAIL_HOST
        send_mail(subject,message,from_email,[to_email])

    def Activate_Email(self,request,user,to_email):
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
        else:
            messages.error(request, f'Problem sending email to {to_email}, check if you typed it correctly.')
        return Response({'message':'Successfully register user account.'})

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
        mail_subject = "Verify your account with OTP."
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

class VerifyViaEmailViews(viewsets.ViewSet):
    token_generator = default_token_generator
    account_activation_token = account_activation_token
    @action(detail=False, methods=['get'])  
    def verify_email(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = UserAccount.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, UserAccount.DoesNotExist):
            user = None
        if user is not None and account_activation_token.check_token(user, token):
            user.activate_account()
            return Response({'message': 'Email verified successfully. You can now log in.'}, status=status.HTTP_201_CREATED)
        else:
            return Response({'message': 'Invalid email verification link.'}, status=status.HTTP_401_UNAUTHORIZED)
    
    @action(detail=False, methods=['post'])  
    def verify_email_t(self, request):
        serializer = UidAndTokenSerializer(data=request.data,context={"view": self})
        serializer.is_valid(raise_exception=True)
        user = serializer.user
        user.activate_account()
        user.save()
        return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post']) 
    def reset_password_confirm(self, request, encryptemail):
        serializer = ResetPasswordEmailSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            decode_email = FunctionView()
            email = decode_email.decode_email(encryptemail)
            user = UserAccount.objects.get(email=email)
        except (TypeError, ValueError, OverflowError, UserAccount.DoesNotExist):
            user = None
        serializer.user.set_password(serializer.validated_data["new_password"])
        serializer.user.save()
        update_session_auth_hash(request, user)
        return Response({'message': 'Thay đổi mật khẩu thành công'}, status=status.HTTP_200_OK)

class UserViewSet(viewsets.ViewSet):

    @action(detail=False, methods=['post'])
    def perform_create(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()  
        to = [get_user_email(user)]
        signals.user_registered.send(
            sender=self.__class__, user=user, request=self.request
        )
        if settings.SEND_ACTIVATION_EMAIL:
            context = {"user": user}
            if settings.EMAIL.activation(self.request, context).send(to):
                return Response('send mail succces')
            else: 
                return Response('send mail fails')
        elif settings.SEND_CONFIRMATION_EMAIL:
            settings.EMAIL.confirmation(self.request, context).send(to)
        return Response(status=status.HTTP_204_NO_CONTENT)
    
    @action(detail=False, methods=['post'])
    def signup(self, request):
        serializer = CreateAccountUser(data=request.data)
        data = {}
        if serializer.is_valid():
            try:
                func = FunctionView()
                user = serializer.save()  
                to_email = user.email
                func.Activate_Email(request,user,to_email)
                data['response'] = 'User registered successfully. Please check your email for verification.'
                data['email'] = to_email
                data['username'] = user.username
                if Token.objects.filter(user=user).exists():
                    token = Token.objects.get(user=user)
                else:
                    token = Token.objects.create(user=user)
                data['token'] = token.key
                data['send_email'] = True 
            except Exception as e:
                data['response_error'] = f'Error sending email: {str(e)}' 
                data['send_email'] = False 
        else:
            response=serializer.errors
            return Response(response, status=status.HTTP_400_BAD_REQUEST)
        return Response(data,status=status.HTTP_200_OK)
    
    @action(detail=False, methods=['post'])
    def signup_backup(self, request):
        serializer = UserSerializer(data=request.data)
        data={}
        if serializer.is_valid():
            user = serializer.save()
            data['response']='User registered successfully'
            data['email'] = user.email
            data['username']= user.username
            token,_ = Token.objects.get_or_create(user=user)
            data['token'] = token.key
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        return Response(data,status=status.HTTP_201_CREATED)
    
    @action(detail=False, methods=['post'])
    def login(self, request):
        serializer = TokenCreateSerializer(data=request.data,context={"request": request})
        serializer.is_valid(raise_exception=True)
        token = utils.login_user(self.request, serializer.user)
        token_serializer_class = settings.SERIALIZERS.token
        
        if settings.CREATE_SESSION_ON_LOGIN:
            update_session_auth_hash(self.request, self.request.user)
        return Response(
            data=token_serializer_class(token).data, status=status.HTTP_200_OK
        )
    
    @action(detail=False, methods=['post'])
    def logout(self, request):
        if request.user.is_authenticated:
            logout(request)
            return Response({'message': 'Logout successful'},status=status.HTTP_200_OK)
        else:
            return Response({'error': 'User is not authenticated'}, status=status.HTTP_401_UNAUTHORIZED)

class SetViews(APIView):
    authentication_classes = [BasicAuthentication,SessionAuthentication,TokenAuthentication]
    permission_classes =[IsAuthenticated]
    def test_token_api(self, request):
        user = request.user
        return Response({'message': f'{user.username} is authenticated and be allowed and to work with {user.email}'},status=status.HTTP_200_OK)
    def get(self, request):
        return self.test_token_api(request)
    
class ChangePasswordView(viewsets.ViewSet):
    @action(detail=False, methods=['post'])   
    def reset_password(self,request):
        data={}
        serializer = Email_password(data=request.data)
        serializer.is_valid(raise_exception=True)
        email =  serializer.validated_data.get('email')
        try:
            func= FunctionView()
            func.resetpassword_via_Email(request,email)
            data['Response'] = "Succsesfully send otp to your email"
            data['send_email'] = True
            return Response(data, status=status.HTTP_200_OK)
        except Exception as e:
            data['response_error'] = f'Error sending email: {str(e)}' 
            data['send_email'] = False 
            return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    permission_classes = [IsAuthenticated]
    @action(detail=False, methods=['post'])
    def change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        self.request.user.set_password(serializer.validated_data['new_password'])
        self.request.user.save()
        if settings.LOGOUT_ON_PASSWORD_CHANGE:
            logout(self.request)
        return Response({"message": "Password changed successfully"}, status=status.HTTP_200_OK)
          
@api_view(['POST'])
def link_resetpassword_email_api(request,encryptemail):
    serializer = ResetPasswordEmailSerializer(data=request.data)
    if serializer.is_valid():
        try:
            decode_email = FunctionView()
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
        update_session_auth_hash(request, user)
        return Response({'message': 'Thay đổi mật khẩu thành công'}, status=status.HTTP_200_OK)
    else:
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

@api_view(['GET'])
def verify_email_api_view(request, uidb64, token):
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

