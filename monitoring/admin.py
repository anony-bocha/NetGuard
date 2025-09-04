from django.contrib import admin
from .models import Asset, AttackType, Scan, Alert

admin.site.register(Asset)
admin.site.register(AttackType)
admin.site.register(Scan)
admin.site.register(Alert)
