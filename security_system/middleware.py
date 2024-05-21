import logging

from django.conf import settings
from django.db.models import Q
from django.http import HttpResponseForbidden, HttpResponseNotFound
from django.utils import timezone

from security_system.models import BlacklistUser, BlacklistIPAddress
from security_system.services import XSSAttackHandler, SQLInjectionAttackHandler, HTMLInjectionAttackHandler, \
    RFIAttackHandler

logger = logging.getLogger('security_system')

attack_attempts_from_user = {}
attack_attempts_from_ip_address = {}


try:
    ALLOWED_HOSTS_ADMIN = settings.ALLOWED_HOSTS_ADMIN
except AttributeError:
    ALLOWED_HOSTS_ADMIN = []
    logging.warning('ALLOWED_HOSTS_ADMIN not set in settings.py')


class SecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.blocked_response = HttpResponseForbidden()

    def __call__(self, request):
        response = self.get_response(request)
        user = request.user
        ip_address = self.get_client_ip_address(request)

        attack_handler = self.is_attack(request)

        if attack_handler:
            attack_attempts_from_user[user] = attack_attempts_from_user.get(user, 0) + 1
            attack_attempts_from_ip_address[ip_address] = attack_attempts_from_ip_address.get(ip_address, 0) + 1
            if user.is_authenticated and attack_attempts_from_user[user] == attack_handler.number_attempts_before_ban:
                attack_handler.block_user() if not self.is_user_blocked(user) else None
                logger.info(f'Attack blocked for user {user.username}, reason: {attack_handler.reason}')
            if attack_attempts_from_ip_address[ip_address] == attack_handler.number_attempts_before_ban:
                attack_handler.block_ip_address(ip_address) if not self.is_ip_address_blocked(ip_address) else None
                logger.info(f'Attack blocked for ip address {ip_address}, reason: {attack_handler.reason}')

        if request.path.startswith('/admin'):
            return self.restrict_admin_url(request)
        if (user.is_authenticated and self.is_user_blocked(user)) or self.is_ip_address_blocked(ip_address):
            return self.blocked_response
        return response

    def restrict_admin_url(self, request):
        if self.get_client_ip_address(request) not in ALLOWED_HOSTS_ADMIN:
            return HttpResponseNotFound()
        return self.get_response(request)

    @staticmethod
    def get_client_ip_address(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR')
        return ip_address

    @staticmethod
    def is_attack(request):
        attack_handlers = [
            XSSAttackHandler(request),
            HTMLInjectionAttackHandler(request),
            SQLInjectionAttackHandler(request),
            RFIAttackHandler(request),
        ]

        for attack_handler in attack_handlers:
            if attack_handler.check():
                return attack_handler
        return False

    @staticmethod
    def is_user_blocked(user):
        return BlacklistUser.objects.filter(
            Q(user=user)
            & Q(end_of_blocking__gte=timezone.now())
        ).exists()

    @staticmethod
    def is_ip_address_blocked(ip_address):
        return BlacklistIPAddress.objects.filter(
            Q(ip_address=ip_address)
            & Q(end_of_blocking__gte=timezone.now())
        ).exists()
