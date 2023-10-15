
from django.urls import path,include
from rest_framework.routers import DefaultRouter


from django.contrib.auth import get_user_model
from accounts import views

router = DefaultRouter()
router.register(r'users', views.UserViewSet, basename='users')


User = get_user_model()

urlpatterns = router.urls
