from django.conf import settings
from django.core.cache import caches, InvalidCacheBackendError
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

from django_saml2_auth import utils
from django_saml2_auth.cache import DjangoCache
from django_saml2_auth.plugins import SamlClientPlugin
from django_saml2_auth.views import _get_metadata, _handle_saml_payload, _get_config


class DefaultSamlClientPlugin(SamlClientPlugin):
    KEY = 'DEFAULT'
    # use a singleton since SAML2 stores user data on the object
    _client = None

    @classmethod
    def get_client(cls, domain):
        if cls._client is None:
            saml_settings = _get_config(domain)

            spConfig = Saml2Config()
            spConfig.load(saml_settings)
            spConfig.allow_unknown_attributes = settings.SAML2_AUTH.get('ALLOW_UNKNOWN_ATTRS', True)

            # try to use a centralized identity cache
            cache = None
            try:
                cache_name = settings.SAML2_AUTH.get('CACHE', 'default')
                cache = DjangoCache(cache=caches[cache_name])
            except InvalidCacheBackendError:
                pass

            cls._client = Saml2Client(config=spConfig, identity_cache=cache)
        return cls._client
