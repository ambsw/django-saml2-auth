#!/usr/bin/env python
# -*- coding:utf-8 -*-
"""
The standard internal workflow for django_saml2_auth is:

 1. Login request triggers _signin() which redirects the user to the IdP with an appropriate payload
    - If next= was sent to this view, it's cached in the session under login_next_view
 2. The IdP response is relayed (by the client) to _handle_saml_payload().  This method will
    1. Call _get_user() to convert the payload into a user.  _get_user() will:
       1. Call _error if no SAMLResponse is found
       2. Call _get_saml_client() -- which calls _get_metadata() -- to get a SAML parser
       3. Call _idp_error() if the IdP request is malformed
       4. Extract user attributes using ATTRIBUTES_MAP
       5. If a user does not exist and user creation is allowed, call _create_user()
       6. If a user does not exist and user creation is NOT allowed, call _local_denied()
    2. Call _local_denied() if the user returned by _get_user is not allowed to login locally
    2. Call _approved() if the user has been authenticated successfully
 3. Approved will redirect the user based on several conditions:
    1. If USE_JWT is enabled, it will construct a JWT token and redirect to the first available of:
       1. FRONTEND_URL
       2. login_next_url from the signin request
       3. default_next_url() i.e. DEFAULT_URL or admin:index
    2. If the user was newly created (and the welcome template exists), the user will be redirected to welcome_view()
    3. If login_next_view was set in _signin(), the user will be redirected there
    4. Otherwise, the user will be redirected to DEFAULT_NEXT_URL
 4. Logout requests trigger _signout()
    1. After the user is logged out, they are redirected to signout_view()
"""
from django import get_version
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from pkg_resources import parse_version

from django_saml2_auth import plugins, signals
# default User or custom User. Now both will work.
from django_saml2_auth.utils import _handle_plugins

try:
    import urllib2 as _urllib
except ImportError:
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


def signin(request):
    """Handles login requests, usually by redirecting users to the SAML IdP"""
    signals.before_signin.send(signin, request=request)
    return _handle_plugins(
        'SIGNIN',
        plugins=plugins.SigninPlugin,
        method_name=plugins.SigninPlugin.signin.__name__,
        args=(request,)
    )


def signout(request):
    """Handles a logout request locally and may or may not forward to IdP"""
    signals.before_signout.send(signin, request=request)
    return _handle_plugins(
        'SIGNIN',
        plugins=plugins.SignoutPlugin,
        method_name=plugins.SignoutPlugin.signout.__name__,
        args=(request,)
    )


@csrf_exempt
def _handle_saml_payload(request):
    """Accepts and handles a request from an IDP, by default depending on _get_user"""
    return _handle_plugins(
        'SIGNIN',
        plugins=plugins.SamlPayloadPlugin,
        method_name=plugins.SamlPayloadPlugin.handle_saml_payload.__name__,
        args=(request,)
    )


@login_required
def _approved(request):
    """Handles a successful authentication, including both IdP and local checks"""
    return _handle_plugins(
        'CREATE_USER',
        plugins=plugins.ApprovedPlugin,
        method_name=plugins.ApprovedPlugin.approved.__name__,
        args=(request,)
    )


def _idp_error(request, reason=None):
    """Generate response to be returned to sender when the IdP denies the authentication"""
    signals.before_idp_denied.send(_create_new_user, request=request)
    return _handle_plugins(
        'IDP_DENIED',
        plugins=plugins.IdpErrorPlugin,
        method_name=plugins.IdpErrorPlugin.error.__name__,
        args=(request, reason)
    )


def _local_denied(request, reason=None):
    """Generate response to be returned to sender when the local application denies the authentication"""
    signals.before_local_denied.send(_create_new_user, request=request)
    return _handle_plugins(
        'LOCAL_DENIED',
        plugins=plugins.LocalDeniedPlugin,
        method_name=plugins.LocalDeniedPlugin.denied.__name__,
        args=(request, reason)
    )


def _get_user(request):
    """Gets the user from the SAML payload in the request usually using a client from _get_saml_client and handles
    missing users, including calling _create_new_user if appropriate"""
    signals.before_get_user.send(request)
    user = _handle_plugins(
        'GET_USER',
        plugins=plugins.GetUserPlugin,
        method_name=plugins.GetUserPlugin.get_user.__name__,
        args=(request,)
    )
    signals.after_get_user.send(request, user)
    return user


def _get_saml_client(domain):
    """Genereate a class able to process SAML data, normally configured by _get_metadata"""
    return _handle_plugins(
        'CREATE_USER',
        plugins=plugins.SamlClientPlugin,
        method_name=plugins.SamlClientPlugin.get_client.__name__,
        args=(domain,)
    )


def _get_metadata():
    """Constructs appropriate SAML metadata, usually based on the settings file"""
    return _handle_plugins(
        'METADATA',
        plugins=plugins.MetadataPlugin,
        method_name=plugins.MetadataPlugin.get_metadata.__name__,
    )


def _create_new_user(kwargs):
    """Creates a new user in the system based on User attributes in kwargs."""
    signals.before_create_user.send(_create_new_user, kwargs=kwargs)  # intentionally mutable
    user = _handle_plugins(
        'CREATE_USER',
        plugins=plugins.CreateUserPlugin,
        method_name=plugins.CreateUserPlugin.create_user.__name__,
        args=(kwargs,)
    )
    signals.after_create_user.send(_create_new_user, user=user)
    return user
