from django.conf import settings
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST

from django_saml2_auth import utils
from django_saml2_auth.plugins import ConfigPlugin
from django_saml2_auth.views import _get_metadata, _handle_saml_payload


class DefaultConfigPlugin(ConfigPlugin):
    KEY = 'DEFAULT'

    @classmethod
    def get_config(cls, domain):
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
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': False,
                    'force_authn': settings.SAML2_AUTH.get('ALWAYS_AUTHENTICATE', False),
                },
            },
        }

        if 'ENTITY_ID' in settings.SAML2_AUTH:
            saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

        if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
            saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

        if 'ACCEPTED_TIME_DIFF' in settings.SAML2_AUTH:
            saml_settings['accepted_time_diff'] = settings.SAML2_AUTH['ACCEPTED_TIME_DIFF']

        return saml_settings
