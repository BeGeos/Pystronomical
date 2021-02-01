from django.contrib import admin
from .models import UserStatus, AuthKeys, SecurityCodes, Recovery, Constellation, Star, Image

# Register your models here.
admin.site.register(UserStatus)
admin.site.register(AuthKeys)
admin.site.register(SecurityCodes)
admin.site.register(Recovery)
admin.site.register(Constellation)
admin.site.register(Star)
admin.site.register(Image)
