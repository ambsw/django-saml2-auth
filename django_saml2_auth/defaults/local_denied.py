from django_saml2_auth.plugins import LocalDeniedPlugin
from django_saml2_auth.views import _idp_error


class DefaultLocalDeniedPlugin(LocalDeniedPlugin):
    """By default, users were redirected to the standard denied page for any error."""
    NAME = 'DEFAULT'

    @classmethod
    def denied(cls, request, reason=None):
        """replicate original behavior"""
        return _idp_error(request)
