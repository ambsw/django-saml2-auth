import django.dispatch

before_create = django.dispatch.Signal(providing_args=["username", "email", "firstname", "lastname"])
after_create = django.dispatch.Signal(providing_args=["user"])
