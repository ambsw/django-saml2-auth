import django.dispatch

before_create = django.dispatch.Signal(providing_args=["username", "email", "firstname", "lastname"])
after_create = django.dispatch.Signal(providing_args=["user"])
before_idp_denied = django.dispatch.Signal(providing_args=["request"])
before_local_denied = django.dispatch.Signal(providing_args=["request"])
before_error = django.dispatch.Signal(providing_args=["request"])
