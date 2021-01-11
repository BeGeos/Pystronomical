from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from django.contrib.auth.forms import SetPasswordForm
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.contrib.auth import update_session_auth_hash
from .models import UserStatus, User, AuthKeys, SecurityCodes, Recovery
from .forms import UserRegisterForm, EmailUpdateForm
import requests, string, random
from datetime import datetime, timedelta
from Pystronomical.env import secret_keys


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
    return int(code)


def ext_generator(num=24):
    alphabet = string.ascii_letters
    extension = ''
    for _ in range(num):
        extension += random.choice(alphabet)
    return extension


# Main website views
def home(request):
    if request.user.is_authenticated:
        keys = AuthKeys.objects.filter(user_id=request.user)
        for key in keys:
            if key.expiration_date <= datetime.now().timestamp():
                delete_request(request.user.id, key)
                key.delete()
    else:
        keys = None
    context = {
        'keys': keys,
        'name': request.user.username
    }
    return render(request, 'home.html', context)


def create_user_view(request):
    if request.user.is_authenticated:
        return redirect('homepage')
    if request.method == 'GET':
        form = UserRegisterForm()
        context = {'form': form}
        return render(request, 'create-user.html', context)
    if request.method == 'POST':
        form = UserRegisterForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            user = User.objects.filter(username=username).first()
            UserStatus.objects.create(user_id=user)
            security_code = security_code_generator()
            exp = datetime.now() + timedelta(seconds=600)
            sc = SecurityCodes.objects.create(user_id=user, code=security_code,
                                              expiration_date=int(exp.timestamp()))
            # TODO send email with verification code
            messages.success(request, f'Thanks {username}! Your account was created successfully')
            return redirect('homepage')

        messages.error(request, form.errors)
        return redirect('create-user')


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
            return redirect('homepage')
        messages.error(request, f'{user.username} is not yet confirmed. Please follow verification steps to '
                                f'request an authorisation key')
        return redirect('homepage')
    return redirect('login')


def delete_auth_key(request, slug):
    key = AuthKeys.objects.filter(key=slug).first()
    delete_request(key.user_id.id, key.key)
    key.delete()
    messages.success(request, 'Key was deleted successfully!')
    return redirect('homepage')


def verification(request):
    if request.user.is_authenticated:
        if request.method == 'GET':
            return render(request, 'security-code.html')
        if request.method == 'POST':
            security_code = request.POST.get('security_code')
            print(security_code)
            ssc = SecurityCodes.objects.filter(user_id=request.user.id, code=security_code).first()

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
                return redirect('homepage')
            messages.error(request, 'The code is not valid')
            return redirect('verification')
    return redirect('login')


def new_code_request(request):
    if request.user.is_authenticated:
        if request.user.userstatus.confirmed:
            messages.info(request, 'You are already a confirmed user')
            return redirect('homepage')

        security_code = SecurityCodes.objects.filter(user_id=request.user).first()
        if security_code:
            security_code.delete()
        new_code = security_code_generator()
        exp = datetime.now() + timedelta(seconds=600)
        ssc = SecurityCodes.objects.create(user_id=request.user, code=new_code,
                                           expiration_date=int(exp.timestamp()))
        # TODO send email with new verification code
        messages.success(request, 'A new code was sent. Please, check your email!')
        return redirect('homepage')
    return redirect('login')


def recovery_password(request):
    if request.user.is_authenticated:
        email = request.user.email
        messages.info(request, f'A message was sent to {email} to reset the password')
        return redirect('homepage')
    else:
        if request.method == 'POST':
            base_url = 'http://localhost:8000/account/recovery/'
            email = request.POST.get('email')
            user = User.objects.filter(email=email).first()
            if not user:
                messages.error(request, 'This email address does not exist')
                return redirect('homepage')
            recovery_check = Recovery.objects.filter(user_id=user).first()
            if recovery_check:
                recovery_check.delete()
            url_code = ext_generator(16)
            exp = datetime.now() + timedelta(days=1)
            recovery_link = Recovery.objects.create(user_id=user, url_code=url_code,
                                                    expiration_date=int(exp.timestamp()))
            link = base_url + url_code
            # TODO send email with link
            messages.success(request, f'An email was sent to {email} with the recovery link')
            messages.info(request, f'This is your link: {link}')
            return redirect('homepage')
        return render(request, 'pass-recovery.html')


def new_password(request, slug):
    code = get_object_or_404(Recovery, url_code=slug)
    now = datetime.now().timestamp()
    user = User.objects.get(id=code.user_id.id)
    if code.expiration_date <= now:
        code.delete()
        messages.error(request, 'Link is expired')
        return redirect('homepage')
    form = SetPasswordForm(user)

    if request.method == 'POST':
        user = User.objects.get(id=code.user_id.id)
        form = SetPasswordForm(user=user, data=request.POST)

        if form.is_valid():
            form.save()
            code.delete()
            messages.success(request, f'Password was changed successfully for {user.username}')
            return redirect('login')
        else:
            messages.info(request, form.errors)
            messages.error(request, 'Please correct the error')
            return redirect('new-password', slug=slug)
    return render(request, 'pass-recovery-form.html', context={'form': form, 'username': user.username})


def update_email(request):
    if request.method == 'GET':
        if request.user.is_authenticated:
            form = EmailUpdateForm()
            return render(request, 'update-email.html', context={'form': form})
        else:
            return redirect('login')
    if request.method == 'POST':
        form = EmailUpdateForm(request.POST)
        if form.is_valid():
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
            user.email = form.cleaned_data.get('email')
            user.save()

            # TODO send email with new ss_code

            messages.success(request, f'Email was changed successfully for {request.user.username}')
            return redirect('homepage')
        else:
            messages.error(request, form.errors)
            return redirect('update-email')
