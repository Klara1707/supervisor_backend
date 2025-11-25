
"""
URL configuration for project_name project.

The `urlpatterns` list routes URLs to views.
Docs: https://docs.djangoproject.com/en/5.1/topics/http/urls/
"""
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('src.login.urls')),  # include your app's router & JWT endpoints
]
