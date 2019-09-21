from django.conf import settings
from django.utils.module_loading import import_string
from saml2 import entity

from django_saml2_auth import utils
from django_saml2_auth.errors import IdpError, LocalDenied
from django_saml2_auth.plugins import GetUserPlugin
from django_saml2_auth.utils import User
from django_saml2_auth.views import _get_saml_client, _create_new_user


class DefaultGetUserPlugin(GetUserPlugin):
    KEY = 'DEFAULT'

    @classmethod
    def get_user(cls, request):
        """Return the user or raise an exception"""
        resp = request.POST.get('SAMLResponse', None)

        if not resp:
            raise IdpError("SAMLResponse not found in request")

        saml_client = _get_saml_client(utils.get_current_domain(request))
        authn_response = saml_client.parse_authn_request_response(
            resp, entity.BINDING_HTTP_POST)
        if authn_response is None:
            raise IdpError("SAML Client did not find authentication request")

        user_identity = authn_response.get_identity()
        if user_identity is None:
            raise IdpError("Identity not found in SAML authentication request")

        user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'Email')][0]
        user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('username', 'UserName')][0]
        user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')][0]
        user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'LastName')][0]

        is_new_user = False

        try:
            target_user = User.objects.get(username=user_name)
        except User.DoesNotExist:
            new_user_should_be_created = settings.SAML2_AUTH.get('CREATE_USER', True)
            if new_user_should_be_created:
                kwargs = {
                    'username': user_name,
                    'email': user_email,
                    'first_name': user_first_name,
                    'last_name': user_last_name
                }
                target_user = _create_new_user(kwargs)
                if settings.SAML2_AUTH.get('TRIGGER', {}).get('CREATE_USER', None):
                    import_string(settings.SAML2_AUTH['TRIGGER']['CREATE_USER'])(user_identity)
                is_new_user = True
            else:
                raise LocalDenied("User does not exist and may not be created")

        return target_user, is_new_user
