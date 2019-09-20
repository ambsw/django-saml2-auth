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


def run_plugins(namespace, plugins, method_name, args=()):
    """Generic plugin running architecture"""
    for name in settings.SAML2_AUTH.get('PLUGINS', {}).get(namespace, ['DEFAULT']):
        plugin = plugins.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find {} with key:  {}".format(plugins.__name__, plugin))
        response = getattr(plugin, method_name)(*args)
        if response is not None:
            return response
    raise ImproperlyConfigured("{} plugins did not return a valid object".format(plugins.__name__))


@csrf_exempt
def handle_saml_payload(request):
    """Accepts and handles a request from an IDP, by default depending on _get_user"""
    return run_plugins(
        'SIGNIN',
        plugins=plugins.SamlPayloadPlugin,
        method_name=plugins.SamlPayloadPlugin.handle_saml_payload.__name__,
        args=(request,)
    )


@login_required
def approved(request):
    """Handles a successful authentication, including both IdP and local checks"""
    return run_plugins(
        'CREATE_USER',
        plugins=plugins.ApprovedPlugin,
        method_name=plugins.ApprovedPlugin.approved.__name__,
        args=(request,)
    )


class SamlError(Exception):
    """A standard way to indicate an Error when the plugin is not designed to return a Response"""


def error(request, reason=None):
    """Generate response to be returned to sender due to an error"""
    signals.before_error.send(_create_new_user, request, reason)
    return run_plugins(
        'CREATE_USER',
        plugins=plugins.ErrorPlugin,
        method_name=plugins.ErrorPlugin.error.__name__,
        args=(request, reason)
    )


class IdpDenied(Exception):
    """A standard way to indicate that authentication was denied by the IdP when the plugin is not designed to return a
    Response"""


def idp_denied(request):
    """Generate response to be returned to sender when the IdP denies the authentication"""
    signals.before_idp_denied.send(_create_new_user, request)
    return run_plugins(
        'IDP_DENIED',
        plugins=plugins.IdpDeniedPlugin,
        method_name=plugins.IdpDeniedPlugin.denied.__name__,
        args=(request,)
    )


def local_denied(request):
    """Generate response to be returned to sender when the local application denies the authentication"""
    signals.before_local_denied.send(_create_new_user, request)
    return run_plugins(
        'LOCAL_DENIED',
        plugins=plugins.LocalDeniedPlugin,
        method_name=plugins.LocalDeniedPlugin.denied.__name__,
        args=(request,)
    )


def _get_user(request):
    """Gets the user from the SAML payload in the request usually using a client from _get_saml_client and handles
    missing users, including calling _create_new_user if appropriate"""
    return run_plugins(
        'GET_USER',
        plugins=plugins.GetUserPlugin,
        method_name=plugins.GetUserPlugin.get_user.__name__,
        args=(request,)
    )


def _get_saml_client(domain):
    """Genereate a class able to process SAML data, normally configured by _get_metadata"""
    return run_plugins(
        'CREATE_USER',
        plugins=plugins.SamlClientPlugin,
        method_name=plugins.SamlClientPlugin.get_client.__name__,
        args=(domain,)
    )


def _get_metadata():
    """Constructs appropriate SAML metadata, usually based on the settings file"""
    return run_plugins(
        'METADATA',
        plugins=plugins.MetadataPlugin,
        method_name=plugins.MetadataPlugin.get_metadata.__name__,
    )


def _create_new_user(kwargs):
    """Creates a new user in the system based on User attributes in kwargs."""
    signals.before_create.send(_create_new_user, kwargs)  # intentionally mutable
    user = run_plugins(
        'CREATE_USER',
        plugins=plugins.CreateUserPlugin,
        method_name=plugins.CreateUserPlugin.create_user.__name__,
        args=(kwargs,)
    )
    signals.after_create.send(_create_new_user, user)
    return user


def signin(request):
    """Handles login requests, by default redirecting users to the SAML IdP"""
    signals.before_signin.send(signin, request)
    return run_plugins(
        'SIGNIN',
        plugins=plugins.SigninPlugin,
        method_name=plugins.SigninPlugin.signin.__name__,
        args=(request,)
    )


def signout(request):
    """Handlers a logout request."""
    signals.before_signout.send(signin, request)
    return run_plugins(
        'SIGNIN',
        plugins=plugins.SignoutPlugin,
        method_name=plugins.SignoutPlugin.signout.__name__,
        args=(request,)
    )
