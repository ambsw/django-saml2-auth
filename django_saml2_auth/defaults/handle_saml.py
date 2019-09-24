from django.conf import settings
from django.utils.module_loading import import_string
from saml2.ident import code

from django_saml2_auth import utils
from django_saml2_auth.errors import LocalDenied, IdpError
from django_saml2_auth.plugins import SamlPayloadPlugin
from django_saml2_auth.views import _idp_error, _get_user, _local_denied, _authenticated, _get_saml_client


class DefaultSamlPayloadPlugin(SamlPayloadPlugin):
    """Authenticates user based on SAML object in request"""
    KEY = 'DEFAULT'

    @classmethod
    def handle_saml_payload(cls, request):
        client = _get_saml_client(utils.get_current_domain(request))
        authn = utils.get_authn(request, client)
        user_identity = authn.get_identity()
        if user_identity is None:
            return _idp_error(request, IdpError("Identity not found in SAML authentication request"))

        try:
            # raises exceptions to achieve original response behavior
            target_user, is_new_user = _get_user(user_identity)
        except IdpError as e:
            return _idp_error(request, e)
        except LocalDenied as e:
            return _local_denied(request, e)

        # don't lose next URL during flush
        next_url = request.session.get('login_next_url', None)
        request.session.flush()
        if next_url is not None:
            request.session['login_next_url'] = next_url

        if not target_user.is_active:
            return _local_denied(request, LocalDenied("User is not active."))

        # store user for SLO
        request.session['name_id'] = code(authn.name_id)

        # must be here for legacy access to user_identity
        if settings.SAML2_AUTH.get('TRIGGER', {}).get('BEFORE_LOGIN', None):
            import_string(settings.SAML2_AUTH['TRIGGER']['BEFORE_LOGIN'])(user_identity)

        return _authenticated(request, target_user, is_new_user)
