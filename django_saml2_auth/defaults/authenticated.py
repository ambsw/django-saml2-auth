from django.conf import settings
from django.contrib.auth import login
from django.http import HttpResponseRedirect
from django.template import TemplateDoesNotExist
from rest_auth.utils import jwt_encode

from django_saml2_auth import utils, signals
from django_saml2_auth.plugins import AuthenticatedPlugin
from django_saml2_auth.views import welcome_view


class LoginAuthenticatedPlugin(AuthenticatedPlugin):
    KEY = 'LOGIN'

    @classmethod
    def authenticated(cls, request, user, new_user=False):
        user.backend = 'django.contrib.auth.backends.ModelBackend'
        signals.before_login.send(DefaultAuthenticatedPlugin, user=user)
        login(request, user)
        signals.after_login.send(DefaultAuthenticatedPlugin, user=user)


class JwtAuthenticatedPlugin(AuthenticatedPlugin):
    KEY = 'JWT'

    @classmethod
    def authenticated(cls, request, user, new_user=False):
        if settings.SAML2_AUTH.get('USE_JWT') is True:
            # We use JWT auth send token to frontend
            jwt_token = jwt_encode(user)
            query = '?uid={}&token={}'.format(user.id, jwt_token)

            next_url = request.session.get('login_next_url', utils.default_next_url())
            frontend_url = settings.SAML2_AUTH.get('FRONTEND_URL', next_url)

            return HttpResponseRedirect(frontend_url + query)


class DefaultAuthenticatedPlugin(AuthenticatedPlugin):
    KEY = 'DEFAULT'

    @classmethod
    def authenticated(cls, request, user, new_user=False):
        LoginAuthenticatedPlugin.authenticated(request, user)
        response = JwtAuthenticatedPlugin.authenticated(request, user)
        if response is not None:
            return response

        if new_user:
            try:
                return welcome_view(request)
            except TemplateDoesNotExist:
                pass

        next_url = request.session.get('login_next_url', utils.default_next_url())
        return HttpResponseRedirect(next_url)
