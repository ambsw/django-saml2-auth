from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist

from django_saml2_auth import utils
from django_saml2_auth.plugins import PluginMeta


class ApprovedPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to ApprovedPlugin despite parent Metaclass
    _plugins = {}


class ApprovedPlugin(object, metaclass=ApprovedPluginMeta):

    def approved(self, request):
        raise NotImplementedError


class DefaultApprovedPlugin(ApprovedPlugin):
    def approved(self, request):
        try:
            return render(request, 'django_saml2_auth/welcome.html', {'user': request.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(utils._default_next_url())
