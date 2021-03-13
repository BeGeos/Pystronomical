from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.core.mail import send_mail
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse, Http404
from json import JSONDecodeError
from django.contrib.auth import update_session_auth_hash

from .models import UserStatus, User, AuthKeys, SecurityCodes, Recovery, Constellation, Feedback
from Pystronomical.env import secret_keys
from Pystronomical.functions import verification_email, recovery_email

import requests, string, random
from datetime import datetime, timedelta, timezone
import re


# Main functions to talk to astropy API for database updates
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
# TODO Rethink the process. Move the api keys in 1 database and requests will handle
# TODO all the logic in one place. Flask API will receive True or False and n° of calls
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


# API calls from website to astropy API
def constellation_api_request(constellation):
    url = f"http://localhost:5000/astropy/api/v1/constellation?c={constellation.lower()}"
    payload = {'ADMIN_KEY': secret_keys['ADMIN_KEY']}
    request = requests.post(url, json=payload)

    api_data = request.json()['constellation']

    response = {'abbreviation': api_data['abbreviation'],
                'alias': api_data['alias'],
                'max_latitude': api_data['max_latitude'],
                'min_latitude': api_data['min_latitude'],
                'quadrant': api_data['quadrant'],
                'declination': api_data['declination'],
                'right_ascension': api_data['right_ascension'],
                'name': api_data['name'],
                'main_stars': api_data['stars']}

    return response


def star_api_request(star):
    url = f"http://localhost:5000/astropy/api/v1/star?s={star.lower()}"
    payload = {'ADMIN_KEY': secret_keys['ADMIN_KEY']}
    request = requests.post(url, json=payload)

    api_data = request.json()['star']
    # print(api_data)
    response = {'apparent_magnitude': api_data['apparent_magnitude'],
                'name': api_data['name'],
                'distance': api_data['distance'],
                'declination': api_data['declination'],
                'right_ascension': api_data['right_ascension'],
                'spectral_type': api_data['type'],
                'constellation': api_data['constellation']['name']}

    return response


def where_to_look_api(star, city):
    url = f'http://localhost:5000/astropy/api/v1/where-to-look?s={star}&city={city}'
    payload = {'ADMIN_KEY': secret_keys['ADMIN_KEY']}
    request = requests.post(url, json=payload)
    data = request.json()

    return data


# Weather API one call for where-to-look visibility and cloudiness
def vis_request_api(lat, lon):
    api_key = secret_keys['OPEN_WEATHER_API_KEY']

    url = 'https://api.openweathermap.org/data/2.5/onecall?'
    excluded = "current,minutely,alerts"
    payload = {'appid': api_key, 'lat': lat, 'lon': lon, 'exclude': excluded}
    response = requests.get(url, params=payload)
    data = response.json()

    offset = data['timezone_offset']
    hourly = data['hourly']
    interval = [22, 0, 2, 4]
    info = {}
    for i in range(24):
        local_time = hourly[i]['dt'] + offset
        clock_24h = datetime.fromtimestamp(local_time, timezone.utc)
        time = clock_24h.strftime('%H')
        if int(time) in interval:
            info[time] = {'clouds': hourly[i]['clouds'],
                          'visibility': hourly[i]['visibility'],
                          'icon': hourly[i]['weather'][0]['icon']}
    return info


# Key/codes generators
def key_generator(num=24):  # for API keys
    alphanumeric = string.ascii_letters + string.digits
    key = ''
    for _ in range(num):
        key += random.choice(alphanumeric)
    return key


def security_code_generator(num=6):  # for User registration
    numbers = string.digits
    code = ''
    for _ in range(num):
        code += random.choice(numbers)
    return code


def ext_generator(num=24):  # for URLs recovery links
    alphabet = string.ascii_letters
    extension = ''
    for _ in range(num):
        extension += random.choice(alphabet)
    return extension


def feedback_slug(num=8):
    alphanumeric = string.ascii_letters + string.digits
    slug = ''
    for _ in range(num):
        slug += random.choice(alphanumeric)
    return slug


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

    north = Constellation.objects.filter(hemisphere='N').order_by('name')
    south = Constellation.objects.filter(hemisphere='S').order_by('name')
    context = {
        'north': north,
        'south': south
    }

    return render(request, 'explore.html', context)


def single_constellation(request, constellation):
    if request.method == 'POST':
        star = request.POST.get('star')
        return redirect('star-detail', s=star)

    _list = Constellation.objects.all().order_by('name')
    data = get_object_or_404(Constellation, name=constellation)
    context = constellation_api_request(constellation)
    context['list'] = _list
    context['data'] = data
    return render(request, 'single-constellation.html', context)


def single_star(request, s):
    if request.method == 'POST':
        star = request.POST.get('star')
        return redirect('star-detail', s=star)
    if request.method == 'GET':
        city = request.GET.get('city')
        try:
            context = star_api_request(s)
            const_pic = Constellation.objects.filter(name=context['constellation']).first()
            context['picture'] = const_pic
        except JSONDecodeError:
            messages.error(request, f'{s} was not found!')
            return redirect('explore')
        if city:
            info = where_to_look_api(s, city)  # dict
            lat = int(re.findall(r"([0-9]*)°", info['lat'])[0])
            lon = int(re.findall(r"([0-9]*)°", info['lat'])[0])
            cloud_data = vis_request_api(lat, lon)  # dict

            context['city'] = city
            context['where_to_look'] = info
            context['cloud_data'] = cloud_data
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
        context = {}
        if keys:
            context['key'] = keys
            expired = True
            now = datetime.utcnow().timestamp()
            if keys.expiration_date > now:
                expired = False
            context['expired'] = expired
        else:
            context['key'] = None

        return render(request, 'main-profile.html', context)
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
            exp = datetime.utcnow() + timedelta(days=183)
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
                messages.success(request, 'Thank you for verifying your email address')
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
        return redirect('homepage')

    if request.method == 'POST':
        user = User.objects.get(id=code.user_id.id)
        new_password = request.POST.get('new-password')
        confirm = request.POST.get('confirm-new')

        if new_password != confirm:
            messages.error(request, 'Passwords do not match')
            return redirect('new-password', slug=slug)
        if not is_password_valid(new_password, confirm):
            messages.error(request, 'Password is not valid')
            return redirect('new-password', slug=slug)

        user.set_password(new_password)
        user.save()
        code.delete()
        messages.success(request, f'Password for {user.username} was changed successfully!')
        return redirect('homepage')
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


def feedback_view(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('feedback')
        slug = feedback_slug()
        Feedback.objects.create(name=name, email_address=email,
                                feedback=message, slug=slug)
        return redirect('feedback-success', slug=slug)
    return render(request, 'feedback.html')


def feedback_success_view(request, slug):
    check = get_object_or_404(Feedback, slug=slug)
    check.delete()
    return render(request, 'feedback-success.html')
