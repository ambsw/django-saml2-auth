from django.conf import settings

from django_saml2_auth.plugins import PluginMeta


class MetadataPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to MetadataPluginMeta even though we share the parent architecture
    _plugins = {}


class MetadataPlugin(object, metaclass=MetadataPluginMeta):

    def get_metadata(self):
        raise NotImplementedError


class DefaultMetadataHandler(MetadataPlugin):
    NAME = 'DEFAULT'

    def get_metadata(self):
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
