from django.contrib.auth import logout
from django.shortcuts import render

from django_saml2_auth.plugins import PluginMeta


class SignoutPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to SignoutPlugin despite parent Metaclass
    _plugins = {}


class SignoutPlugin(object, metaclass=SignoutPluginMeta):

    def signout(self, request):
        raise NotImplementedError


class DefaultSignoutPlugin(SignoutPlugin):

    def signout(self, request):
        logout(request)
        return render(request, 'django_saml2_auth/signout.html')
