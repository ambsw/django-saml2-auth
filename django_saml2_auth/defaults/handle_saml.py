from django.conf import settings
from django.utils.module_loading import import_string

from django_saml2_auth import utils
from django_saml2_auth.errors import LocalDenied, IdpError
from django_saml2_auth.plugins import SamlPayloadPlugin
from django_saml2_auth.views import _idp_error, _get_user, _local_denied, _authenticated, _get_saml_client


class DefaultSamlPayloadPlugin(SamlPayloadPlugin):
    """Authenticates user based on SAML object in request"""
    KEY = 'DEFAULT'

    @classmethod
    def handle_saml_payload(cls, request):
        try:
            client = _get_saml_client(utils.get_current_domain(request))
            authn_response = utils.get_authn(request, client)
            user_identity = authn_response.get_identity()
            if user_identity is None:
                raise IdpError("Identity not found in SAML authentication request")
            # raises exceptions to achieve original response behavior
            target_user, is_new_user = _get_user(user_identity)

            request.session.flush()

            if not target_user.is_active:
                raise LocalDenied("User is not active.")

            target_user.backend = 'django.contrib.auth.backends.ModelBackend'
            request.session['name_id'] = authn_response.name_id

            if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
                import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(user_identity)

            return _authenticated(request, target_user, is_new_user)
        except IdpError as e:
            return _idp_error(request, e)
        except LocalDenied as e:
            return _local_denied(request, e)
