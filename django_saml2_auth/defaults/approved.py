from django.http import HttpResponseRedirect
from django.template import TemplateDoesNotExist

from django_saml2_auth import utils
from django_saml2_auth.plugins import ApprovedPlugin
from django_saml2_auth.views import welcome_view


class DefaultApprovedPlugin(ApprovedPlugin):
    def approved(self, request):
        try:
            return welcome_view
        except TemplateDoesNotExist:
            return HttpResponseRedirect(utils.default_next_url())
