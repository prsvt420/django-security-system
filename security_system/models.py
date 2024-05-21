from django.contrib.auth import get_user_model
from django.db import models
from django.utils import timezone


class BlacklistUser(models.Model):
    objects = None

    class Meta:
        db_table = 'blacklist_user'
        verbose_name = 'Blacklist user'
        verbose_name_plural = 'Blacklist users'

    user = models.ForeignKey(to=get_user_model(), on_delete=models.CASCADE, db_index=True)
    reason = models.TextField()
    start_of_blocking = models.DateTimeField(auto_now_add=True)
    end_of_blocking = models.DateTimeField(default=timezone.now() + timezone.timedelta(days=365 * 30))


class BlacklistIPAddress(models.Model):
    objects = None

    class Meta:
        db_table = 'blacklist_ip_address'
        verbose_name = 'Blacklist ip address'
        verbose_name_plural = 'Blacklist ip addresses'

    ip_address = models.GenericIPAddressField(db_index=True)
    reason = models.TextField()
    start_of_blocking = models.DateTimeField(auto_now_add=True)
    end_of_blocking = models.DateTimeField(default=timezone.now() + timezone.timedelta(days=365 * 30))
