from django.http import HttpResponseRedirect

from django_saml2_auth import utils
from django_saml2_auth.plugins import IdpDeniedPlugin
from django_saml2_auth.views import idp_denied


class DefaultDeniedPlugin(IdpDeniedPlugin):
    def denied(self, request, reason=None):
        return HttpResponseRedirect(utils.get_reverse([idp_denied, 'denied', 'django_saml2_auth:denied']))
