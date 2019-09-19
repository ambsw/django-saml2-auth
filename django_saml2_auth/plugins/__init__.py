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