from django.conf import settings
from django.utils.module_loading import import_string

from django_saml2_auth.errors import LocalDenied
from django_saml2_auth.plugins import GetUserPlugin
from django_saml2_auth.utils import User
from django_saml2_auth.views import _create_new_user


class DefaultGetUserPlugin(GetUserPlugin):
    KEY = 'DEFAULT'

    @classmethod
    def get_user(cls, user_identity):
        """Return the user or raise an exception"""
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
