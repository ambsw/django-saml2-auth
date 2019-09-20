class SamlError(Exception):
    """A standard way to indicate an Error when the plugin is not designed to return a Response"""


class IdpDenied(Exception):
    """A standard way to indicate that authentication was denied by the IdP when the plugin is not designed to return a
    Response"""