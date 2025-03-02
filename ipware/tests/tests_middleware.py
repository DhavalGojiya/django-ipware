# -*- coding: utf-8 -*-

from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.test import TestCase, override_settings

from ipware.middleware import IPBanlistMiddleware, IPAllowlistMiddleware


class TestIPBanlistMiddleware(TestCase):
    """Test cases for IPBanlistMiddleware"""

    def setUp(self):
        # Create a mock response function for the middleware
        self.get_response = lambda request: None
        # Create an instance of the middleware
        self.middleware = IPBanlistMiddleware(self.get_response)

    @override_settings(BANNED_IPS=["192.168.1.100"])
    def test_banned_ip_blocked(self):
        """Test that a request from a banned IP raises PermissionDenied."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_X_FORWARDED_FOR": "192.168.1.100, 198.84.193.157",
        }
        with self.assertRaises(PermissionDenied) as context:
            self.middleware(request)
        self.assertEqual(str(context.exception), "Your IP address is banned.")

    @override_settings(BANNED_IPS=["192.168.1.100"])
    def test_allowed_ip_not_blocked(self):
        """Test that a request from a non-banned IP passes through."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "10.0.0.1",
            "HTTP_X_FORWARDED_FOR": "10.0.0.1, 198.84.193.157",
        }
        result = self.middleware(request)
        self.assertIsNone(result)  # Request should pass to next middleware

    @override_settings(BANNED_IPS=[])
    def test_no_banned_ips_setting(self):
        """Test that no blocking occurs if BANNED_IPS is empty."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_X_FORWARDED_FOR": "192.168.1.100, 198.84.193.157",
        }
        result = self.middleware(request)
        self.assertIsNone(result)  # No blocking, request passes through

    @override_settings(BANNED_IPS="not_a_list_or_tuple")
    def test_invalid_banned_ips_setting(self):
        """Test that an invalid BANNED_IPS setting raises ValueError."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_X_FORWARDED_FOR": "192.168.1.100, 198.84.193.157",
        }
        with self.assertRaises(ValueError) as context:
            self.middleware(request)
        self.assertEqual(str(context.exception), "BANNED_IPS must be a list or tuple of IP addresses.")


class TestIPAllowlistMiddleware(TestCase):
    """Test cases for IPAllowlistMiddleware"""

    def setUp(self):
        # Create a mock response function for the middleware
        self.get_response = lambda request: None
        # Create an instance of the middleware
        self.middleware = IPAllowlistMiddleware(self.get_response)

    @override_settings(ALLOWED_IPS=["203.0.113.42"])
    def test_allowed_ip_permitted(self):
        """Test that a request from an allowed IP passes through."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "203.0.113.42",
            "HTTP_X_FORWARDED_FOR": "203.0.113.42, 198.84.193.157",
        }
        result = self.middleware(request)
        self.assertIsNone(result)  # Request should pass to next middleware

    @override_settings(ALLOWED_IPS=["203.0.113.42"])
    def test_not_allowed_ip_blocked(self):
        """Test that a request from a non-allowed IP raises PermissionDenied."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_X_FORWARDED_FOR": "192.168.1.100, 198.84.193.157",
        }
        with self.assertRaises(PermissionDenied) as context:
            self.middleware(request)
        self.assertEqual(str(context.exception), "Your IP address is not allowed.")

    @override_settings(ALLOWED_IPS=None)
    def test_no_allowed_ips_setting(self):
        """Test that no restrictions apply if ALLOWED_IPS is set to `None`."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_X_FORWARDED_FOR": "192.168.1.100, 198.84.193.157",
        }
        result = self.middleware(request)
        self.assertIsNone(result)  # No restrictions, request passes through

    @override_settings(ALLOWED_IPS=[])
    def test_empty_allowed_ips_setting(self):
        """Test that a request with an empty ALLOWED_IPS list raises PermissionDenied."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "192.168.1.100",
            "HTTP_X_FORWARDED_FOR": "192.168.1.100, 198.84.193.157",
        }
        with self.assertRaises(PermissionDenied) as context:
            self.middleware(request)
        self.assertEqual(str(context.exception), "Your IP address is not allowed.")

    @override_settings(ALLOWED_IPS="not_a_list_or_tuple")
    def test_invalid_allowed_ips_setting(self):
        """Test that an invalid ALLOWED_IPS setting raises ValueError."""
        request = HttpRequest()
        request.META = {
            "REMOTE_ADDR": "203.0.113.42",
            "HTTP_X_FORWARDED_FOR": "203.0.113.42, 198.84.193.157",
        }
        with self.assertRaises(ValueError) as context:
            self.middleware(request)
        self.assertEqual(str(context.exception), "ALLOWED_IPS must be a list or tuple of IP addresses.")
