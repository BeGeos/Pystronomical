from django.urls import path
from . import views

urlpatterns =[
    path('create/', views.create_user_view, name='create-user'),
    path('create-auth-key/', views.create_auth_key, name='create-key'),
    path('delete-auth-key/<slug>', views.delete_auth_key, name='delete-key'),
    path('verification/', views.verification, name='verification')
]