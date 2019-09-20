#!/usr/bin/env python
# -*- coding:utf-8 -*-


from django import get_version
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from pkg_resources import parse_version

from django_saml2_auth import plugins, signals

# default User or custom User. Now both will work.

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


def signout_view(request):
    return render(request, 'django_saml2_auth/signout.html')


def welcome_view(request):
    return render(request, 'django_saml2_auth/welcome.html', {'user': request.user})


def denied_view(request):
    return render(request, 'django_saml2_auth/denied.html')


def error_view(request):
    return render(request, 'django_saml2_auth/error.html')


@csrf_exempt
def handle_saml_payload(request):
    """Accepts and handles a request from an IDP, by default depending on _get_user"""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('SIGNIN', ['DEFAULT']):
        plugin = plugins.SamlPayloadPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find AcsPluginPlugin with key:  {}".format(plugin))
        response = plugin.handle_saml_payload(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("AcsPlugin plugins did not return user")


@login_required
def idp_approved(request):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = plugins.ApprovedPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find ApprovedPlugin with key:  {}".format(plugin))
        response = plugin.approved(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("Approved plugins did not return user")


class IdpError(Exception):
    pass


def error(request, error=None):
    """Generate response to be returned to sender due to an error"""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = plugins.ErrorPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find ErrorPlugin with key:  {}".format(plugin))
        response = plugin.error(request, error)
        if response is not None:
            return response
    raise ImproperlyConfigured("Error plugins did not return user")


class IdpDenied(Exception):
    pass


def idp_denied(request):
    signals.before_idp_denied.send(_create_new_user, request)
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = plugins.IdpDeniedPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find DeniedPlugin with key:  {}".format(plugin))
        response = plugin.denied(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("IdpDenied plugins did not return user")


def local_denied(request):
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = plugins.LocalDeniedPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find LocalDeniedPlugin with key:  {}".format(plugin))
        response = plugin.denied(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("LocalDenied plugins did not return user")


def _get_user(request):
    """Gets the user from the SAML request usually using a client from _get_saml_client and creating missing users
    using _create_new_user"""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = plugins.GetUserPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find GetUserPlugin with key:  {}".format(plugin))
        user = plugin._get_user(request)
        if user is not None:
            return user
    raise ImproperlyConfigured("GetUser plugins did not return user")


def _get_saml_client(domain):
    """Genereate a class able to extract SAML data from a message, by default depending on _get_metadata"""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = plugins.SamlClientPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find ClientPlugin with key:  {}".format(plugin))
        saml_client = plugin.get_client(domain)
        if saml_client is not None:
            return saml_client
    raise ImproperlyConfigured("Client plugins did not return user")


def _get_metadata():
    """Constructs appropriate SAML metadata, by defualt based on settings.SAML2_CONFIG"""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('METADATA', ['DEFAULT']):
        plugin = plugins.MetadataPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find MetadataPlugin with key:  {}".format(plugin))
        metadata = plugin.get_metadata(settings.SAML2_AUTH)
        if metadata is not None:
            return metadata
    raise ImproperlyConfigured("Metadata plugins did not return metadata")


def _create_new_user(kwargs):
    """Creates a new user in the system."""
    signals.before_create.send(_create_new_user, kwargs)  # intentionally mutable
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('CREATE_USER', ['DEFAULT']):
        plugin = plugins.CreateUserPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find CreateUserPlugin with key:  {}".format(plugin))
        user = plugin.create_user(kwargs)
        if user is not None:
            signals.after_create.send(_create_new_user, user)
            return user
    raise ImproperlyConfigured("CreateUser did not return user")


def signin(request):
    """Handles login requests, by default redirecting users to the SAML IdP"""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('SIGNIN', ['DEFAULT']):
        plugin = plugins.SigninPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find SigninPluginPlugin with key:  {}".format(plugin))
        response = plugin.signin(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("Signin plugins did not return user")


def signout(request):
    """Handlers a logout request."""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get('SIGNOUT', ['DEFAULT']):
        plugin = plugins.SigninPlugin.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find SignoutPluginPlugin with key:  {}".format(plugin))
        response = plugin.singout(request)
        if response is not None:
            return response
    raise ImproperlyConfigured("Signout plugins did not return user")
