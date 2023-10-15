from django.contrib import admin
from django.urls import path,include,re_path
from rest_framework.routers import DefaultRouter
from accounts.views import UserViewSet
from django.views.generic import TemplateView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('accounts.urls')),
    path('accounts/', include('allauth.urls')),
]
urlpatterns += [re_path(r'^.*', TemplateView.as_view(template_name='index.html'))]