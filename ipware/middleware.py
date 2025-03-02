import logging

from django.conf import settings
from django.core.exceptions import PermissionDenied

from .ip import get_client_ip

# Initialize logger
logger = logging.getLogger(__name__)


class IPBanlistMiddleware:
    """
    Middleware to block requests from IPs listed in `settings.BANNED_IPS`.

    Usage:
    Add 'ipware.middleware.IPBanlistMiddleware' to MIDDLEWARE in your Django settings.py.
    Define `BANNED_IPS` in your Django settings.py as a list of blocked IP addresses.

    Example:
    BANNED_IPS = ["192.168.1.100", "10.0.0.1"]
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        banned_ips = getattr(settings, "BANNED_IPS", [])

        if not isinstance(banned_ips, (list, tuple)):
            raise ValueError("BANNED_IPS must be a list or tuple of IP addresses.")

        client_ip, _ = get_client_ip(request)

        if client_ip in banned_ips:
            logger.warning(f"Blocked IP attempt: {client_ip}")
            raise PermissionDenied("Your IP address is banned.")

        return self.get_response(request)


class IPAllowlistMiddleware:
    """
    Middleware to allow access only to IPs listed in `settings.ALLOWED_IPS`.

    Usage:
    Add 'ipware.middleware.IPAllowlistMiddleware' to MIDDLEWARE in your Django settings.py.
    Define `ALLOWED_IPS` in your Django settings.py as a list of allowed IP addresses.
    If `ALLOWED_IPS` is not defined or None, no IP restrictions are applied.

    Example:
    ALLOWED_IPS = ["203.0.113.42", "198.51.100.24"]
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        allowed_ips = getattr(settings, "ALLOWED_IPS", None)

        if allowed_ips is not None and not isinstance(allowed_ips, (list, tuple)):
            raise ValueError("ALLOWED_IPS must be a list or tuple of IP addresses.")

        client_ip, _ = get_client_ip(request)

        if allowed_ips is not None and client_ip not in allowed_ips:
            logger.warning(f"Unauthorized access attempt from IP: {client_ip}")
            raise PermissionDenied("Your IP address is not allowed.")

        return self.get_response(request)
