import logging
import re
from abc import ABC, abstractmethod

from security_system.models import BlacklistUser, BlacklistIPAddress


logger = logging.getLogger('security_system')


class AbstractAttackHandler(ABC):
    @abstractmethod
    def __init__(self, request):
        self.pattern = r''
        self.request = request
        self.reason = 'Abstract attack'
        self.number_attempts_before_ban = None

    @abstractmethod
    def check(self):
        pass

    @abstractmethod
    def block_user(self):
        pass

    @abstractmethod
    def block_ip_address(self, ip_address):
        ...


class XSSAttackHandler(AbstractAttackHandler):
    def __init__(self, request):
        self.pattern = r'<script.*?>.*?</script>'
        self.request = request
        self.reason = 'XSS attack'
        self.number_attempts_before_ban = 2

    def check(self):
        form_data = self.request.POST or self.request.GET
        for key, value in form_data.items():
            if re.search(self.pattern, value):
                return True
        return False

    def block_user(self):
        user = self.request.user
        BlacklistUser.objects.create(user=user, reason=self.reason).save()

    def block_ip_address(self, ip_address):
        BlacklistIPAddress.objects.create(ip_address=ip_address, reason=self.reason).save()


class HTMLInjectionAttackHandler(AbstractAttackHandler):
    def __init__(self, request):
        self.pattern = r'<.*?>'
        self.request = request
        self.reason = 'HTML injection attack'
        self.number_attempts_before_ban = 2

    def check(self):
        form_data = self.request.POST or self.request.GET
        for key, value in form_data.items():
            if re.search(self.pattern, value):
                return True
        return False

    def block_user(self):
        user = self.request.user
        BlacklistUser.objects.create(user=user, reason=self.reason).save()

    def block_ip_address(self, ip_address):
        BlacklistIPAddress.objects.create(ip_address=ip_address, reason=self.reason).save()


class SQLInjectionAttackHandler(AbstractAttackHandler):
    def __init__(self, request):
        self.pattern = r'(;|`|"|’|--).*|\sOR\s|\sAND\s|\s*(union|select|insert|update|delete|drop|alter)\s*'
        self.request = request
        self.reason = 'SQL injection attack'
        self.number_attempts_before_ban = 5

    def check(self):
        form_data = self.request.POST or self.request.GET
        for key, value in form_data.items():
            if re.search(self.pattern, value, re.IGNORECASE):
                return True
        return False

    def block_user(self):
        user = self.request.user
        BlacklistUser.objects.create(user=user, reason=self.reason).save()

    def block_ip_address(self, ip_address):
        BlacklistIPAddress.objects.create(ip_address=ip_address, reason=self.reason).save()


class RFIAttackHandler(AbstractAttackHandler):
    def __init__(self, request):
        self.pattern = r'\.\./{0,}[^\/]+(?:\/[^\/]+)*'
        self.request = request
        self.reason = 'RFI attack'
        self.number_attempts_before_ban = 5

    def check(self):
        form_data = self.request.POST or self.request.GET
        for key, value in form_data.items():
            if re.search(self.pattern, value):
                return True
        return False

    def block_user(self):
        user = self.request.user
        BlacklistUser.objects.create(user=user, reason=self.reason).save()

    def block_ip_address(self, ip_address):
        BlacklistIPAddress.objects.create(ip_address=ip_address, reason=self.reason).save()
