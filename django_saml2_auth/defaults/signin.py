from django import get_version
from django.http import HttpResponseRedirect
from django.utils.http import is_safe_url
from pkg_resources import parse_version

from django_saml2_auth import utils
from django_saml2_auth.plugins import SigninPlugin
from django_saml2_auth.views import _get_saml_client, _error

try:
    import urlparse as _urlparse
    from urllib import unquote
except:
    import urllib.parse as _urlparse
    from urllib.parse import unquote


class DefaultSigninPlugin(SigninPlugin):
    """Redirect a user to the IdP with an appropriate payload"""
    NAME = 'DEFAULT'

    @classmethod
    def signin(cls, request):

        next_url = request.GET.get('next', utils.default_next_url())

        try:
            if 'next=' in unquote(next_url):
                next_url = _urlparse.parse_qs(_urlparse.urlparse(unquote(next_url)).query)['next'][0]
        except:
            pass

        # Only permit signin requests where the next_url is a safe URL
        if parse_version(get_version()) >= parse_version('2.0'):
            args = (next_url, None)
        else:
            args = (next_url,)

        if not is_safe_url(*args):
            _error(request)

        request.session['login_next_url'] = next_url

        saml_client = _get_saml_client(utils.get_current_domain(request))
        _, info = saml_client.prepare_for_authenticate()

        redirect_url = None

        for key, value in info['headers']:
            if key == 'Location':
                redirect_url = value
                break

        return HttpResponseRedirect(redirect_url)
