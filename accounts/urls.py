# from django.urls import path
# from accounts.views import UserViewSet,SetViews,EmailVerificationView,verify_email_api,Function_password
# from rest_framework.authtoken.views import obtain_auth_token

# urlpatterns = [
#     path('signup/', UserViewSet.as_view({'post': 'signup'}), name='signup'),
#     path('login/', UserViewSet.as_view({'post': 'login'}), name='login'),
#     path('logout/', UserViewSet.as_view({'post': 'logout'}), name='logout'),
#     path('auth_token/', SetViews.as_view(), name='auth'),
#     path('verify_email/<str:uidb64>/<str:token>/', EmailVerificationView.as_view({'get': 'verify_email'}), name='verify_email'),
#     path('change-password/', Function_password.as_view({'post': 'change_password'}), name='change-password'),
#     path('reset-password/', Function_password.as_view({'post': 'reset_password'}), name='reset-password'),
#     path('link_resetpassword_email/<str:encryptemail>/', EmailVerificationView.as_view({'post': 'link_resetpassword_email'}), name='link_resetpassword_email'),
# ]

from django.urls import path,include
from accounts.views import UserViewSet,SetViews,verify_email_api_view,VerifyViaEmailViews,ChangePasswordView,change_password_api,link_resetpassword_email_api
from rest_framework.routers import DefaultRouter
# router = DefaultRouter()
# router.register(r'UserViewSet', UserViewSet, basename='UserViewSet')
# router.register(r'VerifyViaEmailViews', VerifyViaEmailViews, basename='VerifyViaEmailViews')
# router.register(r'ChangePasswordView', ChangePasswordView, basename='ChangePasswordView')
urlpatterns = [
    path('signup_backup/', UserViewSet.as_view({'post': 'signup_backup'}), name='signup_backup'),
    path('signup/', UserViewSet.as_view({'post': 'signup'}), name='signup'),
    path('login/', UserViewSet.as_view({'post': 'login'}), name='login'),
    path('logout/', UserViewSet.as_view({'post': 'logout'}), name='logout'),
    path('auth_token/', SetViews.as_view(), name='auth'),
    path('VerifyViaEmailViews/<str:uidb64>/<str:token>/', VerifyViaEmailViews.as_view({'get': 'verify_email'}), name='VerifyViaEmailViews'),
    path('verify_token/', VerifyViaEmailViews.as_view({'post': 'verify_email_t'}), name='verify_token'),
    path('change_password/', ChangePasswordView.as_view({'post': 'change_password'}), name='change_password'),
    path('reset_password/', ChangePasswordView.as_view({'post': 'reset_password'}), name='reset_password'),
    path('reset_password_confirm/<str:encryptemail>/', VerifyViaEmailViews.as_view({'post': 'reset_password_confirm'}), name='reset_password_confirm'),
    path('link_resetpassword_email_api/<str:encryptemail>/', link_resetpassword_email_api, name='link_resetpassword_email_api'),
    # path('', include(router.urls)),
]