class PluginMeta(type):
    # stores the plugins for this object
    _plugins = {}

    def __init__(cls, name, bases, dct):
        super(PluginMeta, cls).__init__(name, bases, dct)
        package = getattr(cls, 'PACKAGE')
        if package is not None:
            cls._plugins[name] = cls

    def get_plugin(cls, name):
        # validate class-dependent config
        return cls._plugins[name]


class AcsPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to AcsPlugin despite parent Metaclass
    _plugins = {}


class AcsPlugin(object, metaclass=AcsPluginMeta):

    def get_acs(self, request):
        raise NotImplementedError


class ApprovedPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to ApprovedPlugin despite parent Metaclass
    _plugins = {}


class ApprovedPlugin(object, metaclass=ApprovedPluginMeta):

    def approved(self, request):
        raise NotImplementedError


class SamlClientPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to ClientPlugin despite parent Metaclass
    _plugins = {}


class SamlClientPlugin(object, metaclass=SamlClientPluginMeta):

    def get_client(self, domain):
        raise NotImplementedError


class CreateUserPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to MetadataPluginMeta even though we share the parent architecture
    _plugins = {}


class CreateUserPlugin(object, metaclass=CreateUserPluginMeta):

    def create_user(self, username, email, firstname, lastname):
        raise NotImplementedError


class IdpDeniedPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to DeniedPlugin despite parent Metaclass
    _plugins = {}


class IdpDeniedPlugin(object, metaclass=IdpDeniedPluginMeta):

    def denied(self, request):
        raise NotImplementedError


class LocalDeniedPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to DeniedPlugin despite parent Metaclass
    _plugins = {}


class LocalDeniedPlugin(object, metaclass=LocalDeniedPluginMeta):

    def denied(self, request):
        raise NotImplementedError


class ErrorPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to ErrorPlugin despite parent Metaclass
    _plugins = {}


class ErrorPlugin(object, metaclass=ErrorPluginMeta):

    def error(self, request):
        raise NotImplementedError


class GetUserPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to GetUserPlugin despite parent Metaclass
    _plugins = {}


class GetUserPlugin(object, metaclass=GetUserPluginMeta):

    def get_user(self, request):
        raise NotImplementedError


class MetadataPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to MetadataPluginMeta even though we share the parent architecture
    _plugins = {}


class MetadataPlugin(object, metaclass=MetadataPluginMeta):

    def get_metadata(self):
        raise NotImplementedError


class SigninPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to SigninPlugin despite parent Metaclass
    _plugins = {}


class SigninPlugin(object, metaclass=SigninPluginMeta):

    def signin(self, request):
        raise NotImplementedError


class SignoutPluginMeta(PluginMeta):
    NAME = None
    # make sure metadata plugins are "local" to SignoutPlugin despite parent Metaclass
    _plugins = {}


class SignoutPlugin(object, metaclass=SignoutPluginMeta):

    def signout(self, request):
        raise NotImplementedError