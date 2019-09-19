from django_saml2_auth.plugins import LocalDeniedPlugin
from django_saml2_auth.views import idp_denied


class DefaultLocalDeniedPlugin(LocalDeniedPlugin):
    """By default, users were redirected to the standard denied page for any error."""
    def denied(self, request):
        """replicate original behavior"""
        return idp_denied(request)
