from django.core.cache import BaseCache
from saml2.cache import Cache


class AssignmentProxy(object):
    def __init__(self, nested: BaseCache):
        object.__setattr__(self, '_obj', nested)

    def __getattribute__(self, name):
        return getattr(object.__getattribute__(self, "_obj"), name)

    def __delattr__(self, name):
        delattr(object.__getattribute__(self, "_obj"), name)

    def __setattr__(self, name, value):
        setattr(object.__getattribute__(self, "_obj"), name, value)

    def __nonzero__(self):
        return bool(object.__getattribute__(self, "_obj"))

    def __str__(self):
        return str(object.__getattribute__(self, "_obj"))

    def __repr__(self):
        return repr(object.__getattribute__(self, "_obj"))

    def __hash__(self):
        return hash(object.__getattribute__(self, "_obj"))

    def __setitem__(self, k, v):
        object.__getattribute__(self, '_obj').set(k, v)

    def __getitem__(self, k):
        return object.__getattribute__(self, '_obj').get(k)

    def __delitem__(self, k):
        object.__getattribute__(self, '_obj').delete(k)

    def __contains__(self, key):
        return object.__getattribute__(self, '_obj').__contains__(key)


class DjangoCache(Cache):
    """Translates the saml2.cache.Cache interface into operations compatible with Django's Cache interface."""

    def __init__(self, filename=None, cache=None):
        if filename is not None and cache is not None:
            raise ValueError("May not provide filename and cache")
        super().__init__()
        if isinstance(cache, BaseCache):
            # proxy calls to Django's BaseCache interface
            self._db = AssignmentProxy(cache)
        elif cache is not None:
            self._db = cache
            self._sync = True
