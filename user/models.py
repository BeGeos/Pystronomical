from django.db import models
from django.contrib.auth.models import User


# User related models
class UserStatus(models.Model):
    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    attempts = models.IntegerField(default=5)
    calls = models.IntegerField(default=1000)
    confirmed = models.BooleanField(default=False)

    def __repr__(self):
        return f'Status of {self.user_id}'


class AuthKeys(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='auth')
    key = models.CharField(max_length=24, null=False)
    expiration_date = models.IntegerField(null=False)

    def __repr__(self):
        return self.key


class SecurityCodes(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ssc', null=False)
    code = models.IntegerField(null=False)
    expiration_date = models.IntegerField()

    def __repr__(self):
        return f'Security code of {self.user_id.username}'


class Recovery(models.Model):
    user_id = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recovery', null=False)
    url_code = models.CharField(max_length=24, null=False)
    expiration_date = models.IntegerField()

    def __repr__(self):
        return self.url_code
