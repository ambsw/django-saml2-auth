#!/usr/bin/env python
# -*- coding:utf-8 -*-


from django import get_version
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from django.views.decorators.csrf import csrf_exempt
from pkg_resources import parse_version

from django_saml2_auth.plugins.acs import AcsPlugin
from django_saml2_auth.plugins.approved import ApprovedPlugin
from django_saml2_auth.plugins.client import ClientPlugin
from django_saml2_auth.plugins.create_user import CreateUserPlugin
from django_saml2_auth.plugins.denied import DeniedPlugin
from django_saml2_auth.plugins.metadata import MetadataPlugin
# default User or custom User. Now both will work.
from django_saml2_auth.plugins.signin import SigninPlugin

try:
    import urllib2 as _urllib
except:
    import urllib.request as _urllib
    import urllib.error
    import urllib.parse

if parse_version(get_version()) >= parse_version('1.7'):
    pass
else:
    pass


def _get_metadata():
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('METADATA', ['DEFAULT']):
        plugin = MetadataPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find MetadataPlugin with key:  {}".format(plugin))
        metadata = plugin.get_metadata(settings.SAML2_AUTH)
        if metadata is not None:
            return metadata
    raise ImproperlyConfigured("Metadata plugins did not return metadata")


def _get_saml_client(domain):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = ClientPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find ClientPlugin with key:  {}".format(plugin))
        user = plugin.get_client(domain)
        if user is not None:
            return user
    raise ImproperlyConfigured("Client plugins did not return user")


@login_required
def idp_approved(request):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = ApprovedPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find ApprovedPlugin with key:  {}".format(plugin))
        user = plugin.approved(request)
        if user is not None:
            return user
    raise ImproperlyConfigured("Approved plugins did not return user")


def idp_denied(request):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = DeniedPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find DeniedPlugin with key:  {}".format(plugin))
        user = plugin.denied(request)
        if user is not None:
            return user
    raise ImproperlyConfigured("Denied plugins did not return user")


def _create_new_user(username, email, firstname, lastname):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = CreateUserPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find CreateUserPlugin with key:  {}".format(plugin))
        user = plugin.create_user(username, email, firstname, lastname)
        if user is not None:
            return user
    raise ImproperlyConfigured("CreateUser plugins did not return user")


@csrf_exempt
def acs(request):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('SIGNIN', ['DEFAULT']):
        plugin = AcsPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find AcsPluginPlugin with key:  {}".format(plugin))
        response = plugin.get_acs(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("AcsPlugin plugins did not return user")


def signin(request):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('SIGNIN', ['DEFAULT']):
        plugin = SigninPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find SigninPluginPlugin with key:  {}".format(plugin))
        response = plugin.singin(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("SigninPlugin plugins did not return user")


def signout(request):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('SIGNOUT', ['DEFAULT']):
        plugin = SigninPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find SignoutPluginPlugin with key:  {}".format(plugin))
        response = plugin.singout(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("SignoutPlugin plugins did not return user")
