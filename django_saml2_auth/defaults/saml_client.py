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
from django_saml2_auth.views import _get_metadata, _handle_saml_payload


class DefaultSamlClientPlugin(SamlClientPlugin):
    KEY = 'DEFAULT'
    # use a singleton since SAML2 stores user data on the object
    _client = None

    @classmethod
    def get_client(cls, domain):
        if cls._client is None:
            acs_url = domain + utils.get_reverse({_handle_saml_payload, 'acs', 'django_saml2_auth:acs'})
            metadata = _get_metadata()

            saml_settings = {
                'metadata': metadata,
                'service': {
                    'sp': {
                        'endpoints': {
                            'assertion_consumer_service': [
                                (acs_url, BINDING_HTTP_REDIRECT),
                                (acs_url, BINDING_HTTP_POST)
                            ],
                        },
                        'allow_unsolicited': True,
                        'authn_requests_signed': False,
                        'logout_requests_signed': settings.SAML2_AUTH.get('LOGOUT_REQUESTS_SIGNED', True),
                        'want_assertions_signed': True,
                        'want_response_signed': False,
                    },
                },
            }

            if 'ENTITY_ID' in settings.SAML2_AUTH:
                saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

            if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
                saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

            if 'ACCEPTED_TIME_DIFF' in settings.SAML2_AUTH:
                saml_settings['accepted_time_diff'] = settings.SAML2_AUTH['ACCEPTED_TIME_DIFF']

            spConfig = Saml2Config()
            spConfig.load(saml_settings)
            spConfig.allow_unknown_attributes = True

            # try to use a centralized identity cache
            cache = None
            try:
                cache_name = settings.SAML2_AUTH.get('CACHE', 'default')
                cache = DjangoCache(cache=caches[cache_name])
            except InvalidCacheBackendError:
                pass

            cls._client = Saml2Client(config=spConfig, identity_cache=cache)
        return cls._client
