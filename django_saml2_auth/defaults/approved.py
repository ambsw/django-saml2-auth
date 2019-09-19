from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist

from django_saml2_auth import utils
from django_saml2_auth.plugins import ApprovedPlugin


class DefaultApprovedPlugin(ApprovedPlugin):
    def approved(self, request):
        try:
            return render(request, 'django_saml2_auth/welcome.html', {'user': request.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(utils.default_next_url())
