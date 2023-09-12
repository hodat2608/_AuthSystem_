from django.urls import path
from accounts.views import UserViewSet,SetViews,EmailVerificationView,verify_email_api,Function_password
from rest_framework.authtoken.views import obtain_auth_token

urlpatterns = [
    path('signup/', UserViewSet.as_view({'post': 'signup'}), name='signup'),
    path('login/', UserViewSet.as_view({'post': 'login'}), name='login'),
    path('logout/', UserViewSet.as_view({'post': 'logout'}), name='logout'),
    path('auth_token/', SetViews.as_view(), name='auth'),
    path('verify_email/<str:uidb64>/<str:token>/', EmailVerificationView.as_view({'get': 'verify_email'}), name='verify_email'),
    path('change-password/', Function_password.as_view({'post': 'change_password'}), name='change-password'),
]

