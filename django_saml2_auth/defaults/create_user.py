from django import get_version
from django.conf import settings
from django.contrib.auth.models import Group
from pkg_resources import parse_version

# default User or custom User. Now both will work.
from django_saml2_auth.plugins import CreateUserPlugin
from django_saml2_auth.utils import User


class DefaultCreateUser(CreateUserPlugin):
    """Create a user based on the values in the kwargs"""
    KEY = 'DEFAULT'

    @classmethod
    def create_user(cls, kwargs):
        user = User.objects.create(**kwargs)
        # legacy create behavior
        groups = [Group.objects.get(name=x) for x in
                  settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('USER_GROUPS', [])]
        if parse_version(get_version()) >= parse_version('2.0'):
            user.groups.set(groups)
        else:
            user.groups = groups
        user.is_active = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('ACTIVE_STATUS', True)
        user.is_staff = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('STAFF_STATUS', True)
        user.is_superuser = settings.SAML2_AUTH.get('NEW_USER_PROFILE', {}).get('SUPERUSER_STATUS', False)
        user.save()
        return user
