from django.shortcuts import render

from django_saml2_auth.plugins import PluginMeta


class DeniedPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to DeniedPlugin despite parent Metaclass
    _plugins = {}


class DeniedPlugin(object, metaclass=DeniedPluginMeta):

    def denied(self, request):
        raise NotImplementedError


class DefaultDeniedPlugin(DeniedPlugin):
    def denied(self, request):
        return render(request, 'django_saml2_auth/denied.html')
