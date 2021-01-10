from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib import messages
from .models import UserStatus, User, AuthKeys, SecurityCodes, Recovery
from .forms import UserRegisterForm
import requests, string, random
from datetime import datetime, timedelta
from ..Pystronomical.env import secret_keys


# Create your views here.
def home(request):
    keys = AuthKeys.objects.filter(user_id=request.user)
    context = {
        'keys': keys,
        'name': request.user.username
    }
    return render(request, 'home.html', context)


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


# Key/codes generators
def key_generator(num=24):
    alphanumeric = string.ascii_letters + string.digits
    key = ''
    for _ in range(1, num + 1):
        key += random.choice(alphanumeric)
    return key


def security_code_generator(num=6):
    numbers = string.digits
    code = ''
    for _ in range(num):
        code += random.choice(numbers)
    return int(code)


# Main website views
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
        else:
            print(form.errors.as_json())
        messages.error(request, 'Account not created')
        return redirect('verification')


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
    return HttpResponse('redirect to login page/or confirm')


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
                print('code exists')
                print(request.user.id)
                if ssc.expiration_date <= datetime.utcnow().timestamp():
                    ssc.delete()
                    messages.info(request, 'This code has expired')
                    return redirect('verification')
                status = UserStatus.objects.filter(user_id=request.user).first()
                status.confirmed = True
                status.save()
                ssc.delete()
                messages.success(request, 'Thank you, you are now a verified user and can ask for api keys')
                return redirect('homepage')
            messages.error(request, 'The code is not valid')
            return redirect('verification')
    return HttpResponse('login required')

