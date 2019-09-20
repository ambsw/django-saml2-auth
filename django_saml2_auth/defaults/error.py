from django_saml2_auth.plugins import ErrorPlugin
from django_saml2_auth.views import _idp_error


class DefaultErrorPlugin(ErrorPlugin):
    """By default, users were redirected to the standard denied page for any error."""
    NAME = 'DEFAULT'

    @classmethod
    def error(cls, request, reason=None):
        _idp_error(request)
