from django.conf import settings

from django_saml2_auth.plugins import MetadataPlugin


class DefaultMetadataHandler(MetadataPlugin):
    NAME = 'DEFAULT'

    @classmethod
    def get_metadata(cls):
        if 'METADATA_LOCAL_FILE_PATH' in settings.SAML2_AUTH:
            return {
                'local': [settings.SAML2_AUTH['METADATA_LOCAL_FILE_PATH']]
            }
        elif 'METADATA_AUTO_CONF_URL' in settings.SAML2_AUTH:
            return {
                'remote': [
                    {
                        "url": settings.SAML2_AUTH['METADATA_AUTO_CONF_URL'],
                    },
                ]
            }
