# from rest_framework import serializers
# from .models import UserAccount
# from rest_framework.authtoken.models import Token
# from allauth.account.adapter import get_adapter
# from allauth.account.utils import setup_user_email
# from allauth.account.utils import send_email_confirmation
# from allauth.account.models import EmailAddress

# class UserSerializer(serializers.ModelSerializer):
#     password_confirm = serializers.CharField(style={'input_type': 'password'}, write_only = True)
#     class Meta:
#         model = UserAccount
#         fields = ('id', 'email', 'username', 'password','password_confirm')
#         extra_kwargs = {'password': {'write_only': True}}

#     def create(self,validated_data):
#         user = UserAccount(
#             email = self.validated_data['email'],
#             username = self.validated_data['username'],
#         )
#         password = self.validated_data['password']
#         password_confirm = self.validated_data['password_confirm']
#         if password != password_confirm:
#             raise serializers.ValidationError({'password': 'Invalid password confirm'})
#         user.set_password(password)
#         user.save()
#         return user


from rest_framework import serializers
from .models import UserAccount

class UserSerializer(serializers.ModelSerializer):
    password_confirm = serializers.CharField(style={'input_type': 'password'}, write_only=True)

    class Meta:
        model = UserAccount
        fields = ('id', 'email', 'username', 'password', 'password_confirm')
        extra_kwargs = {'password': {'write_only': True}}

    def validate(self, data):
        password = data.get('password')
        password_confirm = data.get('password_confirm')
        if password != password_confirm:
            raise serializers.ValidationError({'password': 'Password and password confirmation do not match'})
        return data

    def create(self, validated_data):
        user = UserAccount(
            email=validated_data['email'],
            username=validated_data['username'],
        )
        user.set_password(validated_data['password'])
        user.save()
        return user
    
class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)
    re_new_password = serializers.CharField(required=True)

class ResetPasswordEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

class ResetPasswordEmailConfirmOTPSerializer(serializers.Serializer):
    new_password = serializers.CharField(required=True)
    re_new_password = serializers.CharField(required=True)