from django.conf import settings
from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
)

from django_saml2_auth import utils
from django_saml2_auth.plugins import SamlClientPlugin
from django_saml2_auth.views import _get_metadata, acs


class DefaultSamlClientPlugin(SamlClientPlugin):

    def get_client(self, domain):
        acs_url = domain + utils.get_reverse({acs, 'acs', 'django_saml2_auth:acs'})
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
                },
            },
        }

        if 'ENTITY_ID' in settings.SAML2_AUTH:
            saml_settings['entityid'] = settings.SAML2_AUTH['ENTITY_ID']

        if 'NAME_ID_FORMAT' in settings.SAML2_AUTH:
            saml_settings['service']['sp']['name_id_format'] = settings.SAML2_AUTH['NAME_ID_FORMAT']

        spConfig = Saml2Config()
        spConfig.load(saml_settings)
        spConfig.allow_unknown_attributes = True
        saml_client = Saml2Client(config=spConfig)
        return saml_client
