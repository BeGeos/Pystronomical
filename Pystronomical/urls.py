"""Pystronomical URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from user import views as user_views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('super/', user_views.update_call_count, name='private-API'),
    path('', user_views.landing_page, name='landing'),
    path('home/', user_views.home, name='homepage'),
    path('account/', include('user.urls')),
    path('how-to-observe/', user_views.how_to_view, name='how-to-observe'),
    path('explore/', user_views.explore_view, name='explore'),
    path('explore/constellation/<str:constellation>', user_views.single_constellation, name='constellation-detail'),
    path('explore/star/<str:s>', user_views.single_star, name='star-detail'),
    path('api/', user_views.api_view, name='api')
]
