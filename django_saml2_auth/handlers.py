from saml2.ident import code

from django_saml2_auth import utils
from django_saml2_auth.views import _get_saml_client


def store_name_id(request):
    """Helper function to cache name_id in session.  Available for use by plugins (not core)."""
    client = _get_saml_client(utils.get_current_domain(request))
    authn = utils.get_authn(request, client)
    request.session['name_id'] = code(authn.get_subject())
