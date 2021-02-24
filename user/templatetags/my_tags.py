from django import template
from datetime import datetime

register = template.Library()


@register.simple_tag()
def convert_timestamp(timestamp):
    return datetime.utcfromtimestamp(timestamp).strftime('%d/%m/%Y')


@register.simple_tag()
def is_expired(expiry, now):
    if expiry > now:
        return False
    return True

