from django.contrib.auth import logout

from django_saml2_auth.plugins import SignoutPlugin
from django_saml2_auth.views import signout_view


class DefaultSignoutPlugin(SignoutPlugin):
    NAME = 'DEFAULT'

    @classmethod
    def signout(cls, request):
        logout(request)
        return signout_view(request)
