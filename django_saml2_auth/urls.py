from django.conf.urls import url

from . import views

app_name = 'django_saml2_auth'

urlpatterns = [
    url(r'^acs/$', views._handle_saml_payload, name="acs"),
    url(r'^welcome/$', views.welcome_view, name="welcome"),
    url(r'^denied/$', views.denied_view, name="denied"),
]
