# app/templatetags/filters.py
from django import template

register = template.Library()

@register.filter
def split(value, sep):
    return value.split(sep)