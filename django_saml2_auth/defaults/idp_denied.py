from django.http import HttpResponseRedirect

from django_saml2_auth import utils
from django_saml2_auth.plugins import IdpDeniedPlugin
from django_saml2_auth.views import _idp_denied


class DefaultDeniedPlugin(IdpDeniedPlugin):
    NAME = 'DEFAULT'

    @classmethod
    def denied(cls, request, reason=None):
        return HttpResponseRedirect(utils.get_reverse([_idp_denied, 'denied', 'django_saml2_auth:denied']))
