from django.urls import include, path

urlpatterns = [
    # Manually expose the SAML2 URLs so we can override the behavior for `denied`
    path('sso/', include('django_saml2_auth.urls', namespace='django_saml2_auth')),
]
