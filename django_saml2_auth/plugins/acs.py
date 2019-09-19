from typing import Dict, Any

from django.conf import settings
from django.contrib.auth import login
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from django.utils.module_loading import import_string
from rest_auth.utils import jwt_encode
from saml2 import (
    entity,
)

from django_saml2_auth import utils
from django_saml2_auth.plugins import PluginMeta
from django_saml2_auth.utils import _default_next_url, get_reverse, User
from django_saml2_auth.views import _get_saml_client, idp_denied, _create_new_user


class AcsPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to AcsPlugin despite parent Metaclass
    _plugins = {}


class AcsPlugin(object, metaclass=AcsPluginMeta):

    def get_acs(self, request):
        raise NotImplementedError


class DefaultAcsPlugin(AcsPlugin):

    def get_acs(self, request):
        saml_client = _get_saml_client(utils.get_current_domain(request))
        resp = request.POST.get('SAMLResponse', None)
        next_url = request.session.get('login_next_url', _default_next_url())

        if not resp:
            return HttpResponseRedirect(utils.get_reverse([idp_denied, 'denied', 'django_saml2_auth:denied']))

        authn_response = saml_client.parse_authn_request_response(
            resp, entity.BINDING_HTTP_POST)
        if authn_response is None:
            return HttpResponseRedirect(utils.get_reverse([idp_denied, 'denied', 'django_saml2_auth:denied']))

        user_identity = authn_response.get_identity()
        if user_identity is None:
            return HttpResponseRedirect(get_reverse([idp_denied, 'denied', 'django_saml2_auth:denied']))

        user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'Email')][0]
        user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('username', 'UserName')][0]
        user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')][0]
        user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'LastName')][0]

        is_new_user = False

        try:
            target_user = User.objects.get(username=user_name)
        except User.DoesNotExist:
            new_user_should_be_created = settings.SAML2_AUTH.get('CREATE_USER', True)
            if new_user_should_be_created:
                target_user = _create_new_user(user_name, user_email, user_first_name, user_last_name)
                if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
                    import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(user_identity)
                is_new_user = True
            else:
                return HttpResponseRedirect(get_reverse([idp_denied, 'denied', 'django_saml2_auth:denied']))
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(user_identity)

        request.session.flush()

        if target_user.is_active:
            target_user.backend = 'django.contrib.auth.backends.ModelBackend'
            login(request, target_user)
        else:
            return HttpResponseRedirect(get_reverse([idp_denied, 'denied', 'django_saml2_auth:denied']))

        if settings.SAML2_AUTH.get('USE_JWT') is True:
            # We use JWT auth send token to frontend
            jwt_token = jwt_encode(target_user)
            query = '?uid={}&token={}'.format(target_user.id, jwt_token)

            frontend_url = settings.SAML2_AUTH.get(
                'FRONTEND_URL', next_url)

            return HttpResponseRedirect(frontend_url + query)

        if is_new_user:
            try:
                return render(request, 'django_saml2_auth/welcome.html', {'user': request.user})
            except TemplateDoesNotExist:
                return HttpResponseRedirect(next_url)
        else:
            return HttpResponseRedirect(next_url)
