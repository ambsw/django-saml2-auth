from django import get_version
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url
from pkg_resources import parse_version

from django_saml2_auth import utils
from django_saml2_auth.plugins import PluginMeta
from django_saml2_auth.views import idp_denied, _get_saml_client


class SigninPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to SigninPlugin despite parent Metaclass
    _plugins = {}


class SigninPlugin(object, metaclass=SigninPluginMeta):

    def signin(self, request):
        raise NotImplementedError


class DefaultSigninPlugin(SigninPlugin):
    def signin(self, request):
        try:
            import urlparse as _urlparse
            from urllib import unquote
        except:
            import urllib.parse as _urlparse
            from urllib.parse import unquote
        next_url = request.GET.get('next', utils._default_next_url())

        try:
            if 'next=' in unquote(next_url):
                next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
        except:
            next_url = request.GET.get('next', utils._default_next_url())

        # Only permit signin requests where the next_url is a safe URL
        if parse_version(get_version()) >= parse_version('2.0'):
            url_ok = is_safe_url(next_url, None)
        else:
            url_ok = is_safe_url(next_url)

        if not url_ok:
            return HttpResponseRedirect(utils.get_reverse([idp_denied, 'denied', 'django_saml2_auth:denied']))

        request.session['login_next_url'] = next_url

        saml_client = _get_saml_client(utils.get_current_domain(request))
        _, info = saml_client.prepare_for_authenticate()

        redirect_url = None

        for key, value in info['headers']:
            if key == 'Location':
                redirect_url = value
                break

        return HttpResponseRedirect(redirect_url)
