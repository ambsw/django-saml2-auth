from django.conf.urls import url

from . import views
# import plugins
# noinspection PyUnresolvedReferences
from . import defaults

app_name = 'django_saml2_auth'

urlpatterns = [
    url(r'^acs/$', views.acs, name="acs"),
    url(r'^welcome/$', views.welcome_view, name="welcome"),
    url(r'^denied/$', views.denied_view, name="denied"),
]
