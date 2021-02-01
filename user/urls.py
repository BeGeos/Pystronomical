from django.urls import path
from . import views

urlpatterns =[
    path('register/', views.create_user_view, name='create-user'),
    path('create-auth-key/', views.create_auth_key, name='create-key'),
    path('delete-auth-key/<slug>', views.delete_auth_key, name='delete-key'),
    path('new-code/', views.new_code_request, name='new-code'),
    path('verification/', views.verification, name='verification'),
    path('recovery/', views.recovery_password, name='recovery-password'),
    path('recovery/<slug>', views.new_password, name='new-password'),
    path('update-email/', views.update_email, name='update-email'),
    path('login/', views.login_user_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile_view, name='main-profile'),
    path('profile/update-password', views.update_password_profile, name='update-password-profile'),
]