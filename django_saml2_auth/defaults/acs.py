from django.conf import settings
from django.contrib.auth import login
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from rest_auth.utils import jwt_encode

from django_saml2_auth.plugins import AcsPlugin
from django_saml2_auth.utils import default_next_url
from django_saml2_auth.views import idp_denied, error, _get_user, local_denied, IdpDenied, IdpError


class DefaultAcsPlugin(AcsPlugin):
    """Authenticates user based on SAML object in request"""

    def get_acs(self, request):
        try:
            target_user, is_new_user = _get_user(request)

            request.session.flush()

            if target_user.is_active:
                target_user.backend = 'django.contrib.auth.backends.ModelBackend'
                login(request, target_user)
            else:
                return local_denied(request)

            next_url = request.session.get('login_next_url', default_next_url())

            if settings.SAML2_AUTH.get('USE_JWT') is True:
                # We use JWT auth send token to frontend
                jwt_token = jwt_encode(target_user)
                query = '?uid={}&token={}'.format(target_user.id, jwt_token)

                frontend_url = settings.SAML2_AUTH.get(
                    'FRONTEND_URL', next_url)

                return HttpResponseRedirect(frontend_url + query)

            if is_new_user:
                try:
                    return render(request, 'django_saml2_auth/welcome.html', {'user': request.user})
                except TemplateDoesNotExist:
                    return HttpResponseRedirect(next_url)
            else:
                return HttpResponseRedirect(next_url)
        except IdpDenied:
            return idp_denied(request)
        except IdpError:
            return error(request)
