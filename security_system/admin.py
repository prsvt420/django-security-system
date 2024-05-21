from django.contrib import admin

from security_system.models import BlacklistUser, BlacklistIPAddress


@admin.register(BlacklistUser)
class BlacklistUserAdmin(admin.ModelAdmin):
    list_display = ('user_id', 'reason', 'start_of_blocking', 'end_of_blocking')


@admin.register(BlacklistIPAddress)
class BlacklistIPAddressAdmin(admin.ModelAdmin):
    list_display = ('ip_address', 'reason', 'start_of_blocking', 'end_of_blocking')
