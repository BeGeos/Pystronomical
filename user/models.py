from django.db import models
from django.db.models.signals import post_save
from django.contrib.auth.models import User, AbstractUser


# User related models
# class User(AbstractUser):
#     attempts = models.IntegerField(default=5)
#     calls = models.IntegerField(default=1000)
#     confirmed = models.BooleanField(default=False)


class UserStatus(models.Model):
    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    attempts = models.IntegerField(default=5)
    calls = models.IntegerField(default=1000)
    confirmed = models.BooleanField(default=False)

    def __str__(self):
        return f'Status of {self.user_id}'


def create_user_status(sender, instance, **kwargs):
    UserStatus.objects.create(user_id=instance)


post_save.connect(create_user_status, sender=User)


class AuthKeys(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='auth')
    key = models.CharField(max_length=24, null=False)
    expiration_date = models.IntegerField(null=False)
    active = models.BooleanField(default=True)

    def __str__(self):
        return self.key


class SecurityCodes(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ssc', null=False)
    code = models.CharField(max_length=6, null=False)
    expiration_date = models.IntegerField()

    def __str__(self):
        return f'Security code of {self.user_id.username}'


class Recovery(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recovery', null=False)
    url_code = models.CharField(max_length=24, null=False)
    expiration_date = models.IntegerField()

    def __str__(self):
        return self.url_code


class Constellation(models.Model):
    HEMISPHERES = [('N', 'North'),
                   ('S', 'South')]

    name = models.CharField(max_length=32, null=False)
    hemisphere = models.CharField(max_length=2, choices=HEMISPHERES, null=True)
    best_seen = models.CharField(max_length=16, null=True)
    alias = models.CharField(max_length=128, null=True)
    min_latitude = models.IntegerField(null=True)
    max_latitude = models.IntegerField(null=True)
    description = models.TextField(null=True)

    def __str__(self):
        return self.name


class Star(models.Model):
    constellation_id = models.ForeignKey(Constellation, on_delete=models.SET_NULL, null=True, related_name='star')
    star = models.CharField(max_length=32)
    description = models.TextField()

    def __str__(self):
        return self.star


class Image(models.Model):
    image = models.ImageField(upload_to='static/images')
    constellation_id = models.OneToOneField(Constellation, on_delete=models.CASCADE, null=False, blank=False)
