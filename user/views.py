from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib.auth.forms import SetPasswordForm
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import update_session_auth_hash
from .models import UserStatus, User, AuthKeys, SecurityCodes, Recovery
from .forms import UserRegisterForm, EmailUpdateForm
import requests, string, random
from datetime import datetime, timedelta
from Pystronomical.env import secret_keys
from Pystronomical.functions import verification_email, recovery_email
import smtplib
from email.message import EmailMessage


# Main functions to talk to API for database updates
def put_request(user_id, api_key, exp):
    url = 'http://localhost:5000/astropy/api/put-auth-key'
    payload = {'admin key': secret_keys['ADMIN_KEY'], 'user id': user_id,
               'api key': api_key, 'exp date': exp}
    r = requests.put(url, data=payload)
    return r.status_code


def delete_request(user_id, api_key):
    url = 'http://localhost:5000/astropy/api/delete-auth-key'
    payload = {'admin key': secret_keys['ADMIN_KEY'], 'user id': user_id,
               'api key': api_key}
    r = requests.delete(url, data=payload)
    return r.status_code


def update_auth_status(user_id, api_key, status):
    url = 'http://localhost:5000/astropy/api/update-auth-status'
    payload = {'admin key': secret_keys['ADMIN_KEY'], 'user id': user_id,
               'api key': api_key, 'status': status}
    r = requests.put(url, data=payload)
    return r.status_code


# Callback from astropy API -- update user call count
@csrf_exempt
def update_call_count(request):
    if request.method != 'POST':
        return JsonResponse({'status': 405, 'message': 'Method not allowed'}, status=405)

    ADMIN_KEY = request.POST.get('ADMIN_KEY')
    if ADMIN_KEY != secret_keys['ADMIN_KEY']:
        return JsonResponse({'status': 403, 'message': 'Unauthorised'}, status=403)

    user_id = request.POST.get('user_id')
    user = User.objects.get(pk=user_id)
    status = UserStatus.objects.get(user_id=user)
    if status.calls == 0:
        return JsonResponse({'calls': 0})
    status.calls -= 1
    status.save()
    return JsonResponse({'calls': status.calls})


# Key/codes generators
def key_generator(num=24):
    alphanumeric = string.ascii_letters + string.digits
    key = ''
    for _ in range(num):
        key += random.choice(alphanumeric)
    return key


def security_code_generator(num=6):
    numbers = string.digits
    code = ''
    for _ in range(num):
        code += random.choice(numbers)
    return code


def ext_generator(num=24):
    alphabet = string.ascii_letters
    extension = ''
    for _ in range(num):
        extension += random.choice(alphabet)
    return extension


# User registration logic
def is_username_valid(username):
    """Check whether or not the given username already exists in the database"""
    user = User.objects.filter(username=username).first()
    if user:
        return False
    else:
        return True


def is_password_valid(password1, password2):
    """Check if both passwords provided are identical"""
    if password1 != password2:
        return False
    return True


# Parameters for sending emails
EMAIL_ADDRESS = secret_keys['EMAIL_ADDRESS']
EMAIL_PASS = secret_keys['EMAIL_PASSWORD']


# Send confirmation emails
def verify_email(user, security_code):
    message = verification_email(user.username, security_code)
    subject = '[Pystronomical] - Please confirm you email address'
    sender = secret_keys['EMAIL_ADDRESS']
    email = user.email
    send_mail(subject=subject, message=message, recipient_list=[email], from_email=sender)
    return


def recovery_password_email(user, link):
    message = recovery_email(user.username, link)
    subject = '[Pystronomical] - Reset your password'
    sender = secret_keys['EMAIL_ADDRESS']
    email = user.email
    send_mail(subject=subject, message=message, recipient_list=[email], from_email=sender)


# Main website views
def landing_page(request):
    return render(request, 'landing-page.html')


def how_to_view(request):
    return render(request, 'how-to-observe.html')


def explore_view(request):
    if request.method == 'POST':
        star = request.POST.get('star')
        return redirect('star-detail', s=star)
    return render(request, 'explore.html')


def single_constellation(request, constellation):
    if request.method == 'POST':
        star = request.POST.get('star')
        return redirect('star-detail', s=star)
    context = {'constellation': constellation}
    return render(request, 'single-constellation.html', context)


def single_star(request, s):
    if request.method == 'POST':
        star = request.POST.get('star')
        return redirect('star-detail', s=star)
    if request.method == 'GET':
        city = request.GET.get('city')
        if city:
            context = {'city': city, 'star': s}
            return render(request, 'single-star.html', context)
        context = {'star': s}
        return render(request, 'single-star.html', context)


def login_user_view(request):
    if request.user.is_authenticated:
        return redirect('homepage')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('homepage')
        else:
            messages.error(request, 'Invalid login credentials')
    return render(request, 'login.html')


def logout_view(request):
    if request.user.is_authenticated:
        logout(request)
        messages.success(request, 'You have Logged Out successfully!')
        return redirect('homepage')
    return redirect(request, 'homepage')


def home(request):
    return render(request, 'homepage.html')


def api_view(request):
    return render(request, 'api.html')


def create_user_view(request):
    if request.user.is_authenticated:
        return redirect('homepage')
    if request.method == 'GET':
        return render(request, 'create-user.html')
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')

        if is_username_valid(username) and is_password_valid(password1, password2):
            new_user = User.objects.create_user(username, email, password1)
            # user = User.objects.filter(username=username).first()
            UserStatus.objects.create(user_id=new_user)
            security_code = security_code_generator()
            exp = datetime.now() + timedelta(seconds=600)
            sc = SecurityCodes.objects.create(user_id=new_user, code=security_code,
                                              expiration_date=int(exp.timestamp()))

            # send_email_verification(new_user, security_code)
            verify_email(new_user, security_code)
            messages.success(request, f'Thanks {username}! Your account was created successfully')
            return redirect('homepage')
        else:
            if not is_username_valid(username):
                messages.info(request, 'Username already exists')
            if not is_password_valid(password1, password2):
                messages.info(request, 'Passwords do not coincide')
            return redirect('create-user')


def profile_view(request):
    if request.user.is_authenticated:
        keys = AuthKeys.objects.filter(user_id=request.user).first()
        if not keys:
            keys = None

        context = {'key': keys}
        return render(request, 'main-profile.html', context)
        pass
    return redirect('login')


def create_auth_key(request):
    if request.user.is_authenticated:
        user = User.objects.get(pk=request.user.id)
        if user.userstatus.confirmed:
            check_key = AuthKeys.objects.filter(user_id=request.user).first()
            if check_key:
                delete_request(request.user.id, check_key.key)  # delete from API db
                check_key.delete()

            key = key_generator()
            exp = datetime.utcnow() + timedelta(seconds=600)
            new_key = AuthKeys.objects.create(user_id=request.user, key=key, expiration_date=int(exp.timestamp()))

            put_request(new_key.user_id.id, new_key.key, new_key.expiration_date)  # Create a new one in API db
            messages.success(request, 'Key created successfully!')
            return redirect('main-profile')
        messages.error(request, f'{user.username} is not yet confirmed. Please follow verification steps to '
                                f'request an authorisation key')
        return redirect('main-profile')
    return redirect('login')


def delete_auth_key(request, slug):
    key = AuthKeys.objects.filter(key=slug).first()
    delete_request(key.user_id.id, key.key)
    key.delete()
    messages.success(request, 'Key was deleted successfully!')
    return redirect('main-profile')


def verification(request):
    if request.user.is_authenticated:
        if request.method == 'GET':
            return render(request, 'security-code.html')
        if request.method == 'POST':
            security_code = request.POST.get('security code')
            # print(security_code)
            ssc = SecurityCodes.objects.filter(user_id=request.user, code=security_code).first()

            if ssc:
                if ssc.expiration_date <= datetime.utcnow().timestamp():
                    ssc.delete()
                    messages.info(request, 'This code has expired')
                    return redirect('verification')
                status = UserStatus.objects.filter(user_id=request.user).first()
                status.confirmed = True
                status.save()
                auth_key = AuthKeys.objects.filter(user_id=request.user).first()
                if auth_key:
                    update_auth_status(request.user.id, auth_key.key, True)
                    auth_key.active = True
                    auth_key.save()
                ssc.delete()
                messages.success(request, 'Thank you, you are now a verified user and can ask for api keys')
                return redirect('main-profile')
            messages.error(request, 'The code is not valid')
            return redirect('verification')
    return redirect('login')


def new_code_request(request):
    if request.user.is_authenticated:
        if request.user.userstatus.confirmed:
            messages.info(request, 'You are already a confirmed user')
            return redirect('main-profile')

        security_code = SecurityCodes.objects.filter(user_id=request.user).first()
        if security_code:
            security_code.delete()
        new_code = security_code_generator()
        exp = datetime.now() + timedelta(seconds=600)
        ssc = SecurityCodes.objects.create(user_id=request.user, code=new_code,
                                           expiration_date=int(exp.timestamp()))
        verify_email(request.user, ssc)
        messages.success(request, 'A new code was sent. Please, check your email!')
        return redirect('verification')
    return redirect('login')


def update_password_profile(request):
    if request.user.is_authenticated:
        if request.method == 'POST':
            old_password = request.POST.get('old-password')
            new_password = request.POST.get('new-password')
            confirm = request.POST.get('confirm-new')
            user = authenticate(username=request.user.username, password=old_password)
            if user is None:
                messages.info(request, 'The password is not correct')
                return redirect('update-password-profile')
            if new_password != confirm:
                messages.info(request, 'New password does not match')
                return redirect('update-password-profile')

            user = request.user
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Your password was changed successfully!')
            return redirect('main-profile')
        return render(request, 'update-pass-profile.html')
    return redirect('login')


def recovery_password(request):
    if request.user.is_authenticated:
        return redirect('update-password-profile')
    else:
        if request.method == 'POST':
            base_url = 'http://localhost:8000/account/recovery/'
            email = request.POST.get('email')
            user = User.objects.filter(email=email).first()
            if not user:
                messages.error(request, 'This email address does not exist')
                return redirect('recovery-password')
            recovery_check = Recovery.objects.filter(user_id=user).first()
            if recovery_check:
                recovery_check.delete()
            url_code = ext_generator(16)
            exp = datetime.now() + timedelta(days=1)
            recovery_link = Recovery.objects.create(user_id=user, url_code=url_code,
                                                    expiration_date=int(exp.timestamp()))
            link = base_url + url_code

            # send_password_recovery(user, link)
            recovery_password_email(user, link)
            messages.success(request, f'An email was sent to {email} with the recovery link')
            # messages.info(request, f'This is your link: {link}')
            return redirect('homepage')
        return render(request, 'new-pass-request.html')


def new_password(request, slug):
    if request.user.is_authenticated:
        return redirect('main-profile')

    code = get_object_or_404(Recovery, url_code=slug)
    now = datetime.now().timestamp()
    user = User.objects.get(id=code.user_id.id)
    if code.expiration_date <= now:
        code.delete()
        messages.error(request, 'Link is expired')
        return redirect('login')

    if request.method == 'POST':
        user = User.objects.get(id=code.user_id.id)
        new_password = request.POST.get('new-password')
        confirm = request.POST.get('confirm-new')

        if new_password != confirm:
            messages.error(request, 'Passwords do not match')
            return redirect('new-password', slug=slug)

        user.set_password(new_password)
        user.save()
        code.delete()
        messages.success(request, f'Password for {user.username} was changed successfully!')
        return redirect('login')
    return render(request, 'pass-recovery-form.html')


def update_email(request):
    if request.user.is_authenticated:

        if request.method == 'POST':
            email = request.POST.get('new-email')

            user = User.objects.get(pk=request.user.id)
            ssc = SecurityCodes.objects.filter(user_id=user).first()
            if ssc:
                ssc.delete()
            new_ssc = security_code_generator()
            exp = datetime.now() + timedelta(seconds=600)
            user_ssc = SecurityCodes.objects.create(user_id=user, code=new_ssc,
                                                    expiration_date=int(exp.timestamp()))
            if user.userstatus.confirmed:
                status = UserStatus.objects.get(user_id=user)
                status.confirmed = False
                status.save()
            auth_key = user.auth.first()
            if auth_key:
                update_auth_status(request.user.id, auth_key.key, False)
                auth_key.active = False
                auth_key.save()
            user.email = email
            user.save()

            # Change message for cases like this -- change email verification
            verify_email(user, user_ssc.code)

            messages.success(request, f'Email was changed successfully for {request.user.username}')
            return redirect('main-profile')

        return render(request, 'change-email-profile.html')
    return redirect('login')
