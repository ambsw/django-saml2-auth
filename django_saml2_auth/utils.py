from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from pkg_resources import parse_version
from saml2 import entity
from saml2.ident import code

from django_saml2_auth.errors import IdpError
from django_saml2_auth.views import _get_saml_client

User = get_user_model()


def default_next_url():
    if 'DEFAULT_NEXT_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['DEFAULT_NEXT_URL']
    # Lazily evaluate this in case we don't have admin loaded.
    return get_reverse('admin:index')


def get_current_domain(request):
    if 'ASSERTION_URL' in settings.SAML2_AUTH:
        return settings.SAML2_AUTH['ASSERTION_URL']
    return '{scheme}://{host}'.format(
        scheme='https' if request.is_secure() else 'http',
        host=request.get_host(),
    )


def get_reverse(objs):
    """In order to support different django version, I have to do this"""
    if parse_version(get_version()) >= parse_version('2.0'):
        from django.urls import reverse
    else:
        from django.core.urlresolvers import reverse
    if objs.__class__.__name__ not in ['list', 'tuple', 'set']:
        objs = [objs]

    for obj in objs:
        try:
            return reverse(obj)
        except:
            pass
    raise Exception(
        'We got a URL reverse issue: %s. This is a known issue but please still submit a ticket at https://github.com/fangli/django-saml2-auth/issues/new' % str(
            objs))


def get_authn(request, saml_client):
    resp = request.POST.get('SAMLResponse', None)

    if not resp:
        raise IdpError("SAMLResponse not found in request")

    authn_response = saml_client.parse_authn_request_response(
        resp, entity.BINDING_HTTP_POST)
    if authn_response is None:
        raise IdpError("SAML Client did not find authentication request")
    return authn_response


def _handle_plugins(namespace, plugins, method_name, args=()):
    """Generic plugin running architecture"""
    names = settings.SAML2_AUTH.get('PLUGINS', {}).get(namespace, ['DEFAULT'])
    for name in names:
        plugin = plugins.get_plugin(name=name)
        if plugin is None:
            raise ImproperlyConfigured("SAML2 auth cannot find {} with key:  {}".format(plugins.__name__, plugin))
        response = getattr(plugin, method_name)(*args)
        if response is not None:
            return response
    raise ImproperlyConfigured("{} plugins did not return a valid object".format(plugins.__name__))


def store_name_id(request):
    """Helper function to cache name_id in session.  Available for use by plugins (not core)."""
    client = _get_saml_client(get_current_domain(request))
    authn = get_authn(request, client)
    request.session['name_id'] = code(authn.get_subject())
