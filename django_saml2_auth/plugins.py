class PluginMeta(type):
    # stores the plugins for this object
    _plugins = {}

    def __init__(cls, name, bases, dct):
        super(PluginMeta, cls).__init__(name, bases, dct)
        cls._plugins[name] = cls

    def get_plugin(cls, name):
        # validate class-dependent config
        return cls._plugins[name]


class SigninPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to SigninPlugin despite parent Metaclass
    _plugins = {}


class SigninPlugin(object, metaclass=SigninPluginMeta):
    """Handles the login action, usually by redirecting a user to the IdP with an appropriate payload."""
    @classmethod
    def signin(cls, request):
        raise NotImplementedError


class SignoutPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to SignoutPlugin despite parent Metaclass
    _plugins = {}


class SignoutPlugin(object, metaclass=SignoutPluginMeta):
    """Handles the logout action, including cascading to SLO if configured."""
    @classmethod
    def signout(cls, request):
        raise NotImplementedError


class SamlPayloadPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to AcsPlugin despite parent Metaclass
    _plugins = {}


class SamlPayloadPlugin(object, metaclass=SamlPayloadPluginMeta):
    """Handles a client request with a SAML payload according to the particular payload semantics."""
    @classmethod
    def handle_saml_payload(cls, request):
        raise NotImplementedError


class ApprovedPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to ApprovedPlugin despite parent Metaclass
    _plugins = {}


class ApprovedPlugin(object, metaclass=ApprovedPluginMeta):
    """Redirects a user after a successful login."""
    @classmethod
    def approved(cls, request, user, new_user=False):
        raise NotImplementedError


class IdpErrorPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to DeniedPlugin despite parent Metaclass
    _plugins = {}


class IdpErrorPlugin(object, metaclass=IdpErrorPluginMeta):
    """Redirects a user after a failed login rejected by the IdP."""
    @classmethod
    def error(cls, request, reason=None):
        raise NotImplementedError


class LocalDeniedPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to DeniedPlugin despite parent Metaclass
    _plugins = {}


class LocalDeniedPlugin(object, metaclass=LocalDeniedPluginMeta):
    """Redirects a user after a failed login due to a local constraint like a deactivated account."""
    @classmethod
    def denied(cls, request, reason=None):
        raise NotImplementedError


class ErrorPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to ErrorPlugin despite parent Metaclass
    _plugins = {}


class ErrorPlugin(object, metaclass=ErrorPluginMeta):
    """Redirects a user after an error has occurred."""
    @classmethod
    def error(cls, request, reason=None):
        raise NotImplementedError


class GetUserPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to GetUserPlugin despite parent Metaclass
    _plugins = {}


class GetUserPlugin(object, metaclass=GetUserPluginMeta):
    """Handles a SAML login by returning the local user for that request."""
    @classmethod
    def get_user(cls, request):
        raise NotImplementedError


class CreateUserPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to MetadataPluginMeta even though we share the parent architecture
    _plugins = {}


class CreateUserPlugin(object, metaclass=CreateUserPluginMeta):
    """Handles a request to create a new user."""
    @classmethod
    def create_user(cls, kwargs):
        raise NotImplementedError


class MetadataPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to MetadataPluginMeta even though we share the parent architecture
    _plugins = {}


class MetadataPlugin(object, metaclass=MetadataPluginMeta):
    """Provides the SAML metadata to be used for initializing a SAML Client."""
    @classmethod
    def get_metadata(cls):
        raise NotImplementedError


class SamlClientPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to ClientPlugin despite parent Metaclass
    _plugins = {}


class SamlClientPlugin(object, metaclass=SamlClientPluginMeta):
    """Returns a SAML client based on the domain and the metadata returned by the MetadataPlugin"""
    @classmethod
    def get_client(cls, domain):
        raise NotImplementedError
