from django.contrib import admin
from .models import UserStatus, AuthKeys, SecurityCodes, Recovery

# Register your models here.
admin.site.register(UserStatus)
admin.site.register(AuthKeys)
admin.site.register(SecurityCodes)
admin.site.register(Recovery)
