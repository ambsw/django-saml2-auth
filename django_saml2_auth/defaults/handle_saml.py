from django.conf import settings
from django.contrib.auth import login
from django.utils.module_loading import import_string

from django_saml2_auth import signals
from django_saml2_auth.errors import LocalDenied, IdpError
from django_saml2_auth.plugins import SamlPayloadPlugin
from django_saml2_auth.views import _idp_error, _get_user, _local_denied, _approved


class DefaultSamlPayloadPlugin(SamlPayloadPlugin):
    """Authenticates user based on SAML object in request"""
    KEY = 'DEFAULT'

    @classmethod
    def handle_saml_payload(cls, request):
        try:
            # raises exceptions to achieve original response behavior
            target_user, is_new_user = _get_user(request)

            request.session.flush()

            if not target_user.is_active:
                raise LocalDenied("User is not active.")

            target_user.backend = 'django.contrib.auth.backends.ModelBackend'

            if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
                import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(target_user)

            signals.before_login.call(target_user)
            login(request, target_user)
            signals.after_login.call(target_user)
            return _approved(request, target_user)
        except IdpError as e:
            return _idp_error(request, e)
        except LocalDenied as e:
            return _local_denied(request, e)
