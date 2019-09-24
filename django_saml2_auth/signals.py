import django.dispatch

before_signin = django.dispatch.Signal(providing_args=["request"])
before_login = django.dispatch.Signal(providing_args=["user"])
after_login = django.dispatch.Signal(providing_args=["user"])
before_signout = django.dispatch.Signal(providing_args=["request"])
before_get_user = django.dispatch.Signal(providing_args=["user_identity"])
after_get_user = django.dispatch.Signal(providing_args=["user_identity", "user"])
before_create_user = django.dispatch.Signal(providing_args=["username", "email", "firstname", "lastname"])
after_create_user = django.dispatch.Signal(providing_args=["user"])
before_idp_denied = django.dispatch.Signal(providing_args=["request"])
before_local_denied = django.dispatch.Signal(providing_args=["request"])
before_error = django.dispatch.Signal(providing_args=["request"])
