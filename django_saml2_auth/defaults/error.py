from django_saml2_auth.plugins import ErrorPlugin
from django_saml2_auth.views import idp_denied


class DefaultErrorPlugin(ErrorPlugin):
    """By default, users were redirected to the standard denied page for any error."""
    def error(self, request):
        idp_denied(request)
