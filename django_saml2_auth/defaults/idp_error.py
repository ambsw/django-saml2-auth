from django.http import HttpResponseRedirect

from django_saml2_auth import utils
from django_saml2_auth.plugins import IdpErrorPlugin
from django_saml2_auth.views import _idp_error


class DefaultIdpErrorPlugin(IdpErrorPlugin):
    NAME = 'DEFAULT'

    @classmethod
    def error(cls, request, reason=None):
        return HttpResponseRedirect(utils.get_reverse([_idp_error, 'denied', 'django_saml2_auth:denied']))
