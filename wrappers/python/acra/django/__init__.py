# coding: utf-8
from django.core import validators
from django.db import models
from django import forms
from django.utils import six
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
import acra

__author__ = 'Lagovas <lagovas.lagovas@gmail.com>'

__all__ = ('CharField', 'EmailField', 'TextField')


class CharField(models.CharField):
    def __init__(self, public_key=None, encoding='utf-8',
                 encoding_errors='ignore', *args, **kwargs):
        super(CharField, self).__init__(*args, **kwargs)
        self._encoding = encoding
        self._encoding_errors = encoding_errors
        if not (public_key or settings.ACRA_SERVER_PUBLIC_KEY):
            raise ValueError("Set public key arg or settings.ACRA_SERVER_PUBLIC_KEY")
        self._public_key = public_key or settings.ACRA_SERVER_PUBLIC_KEY

    def from_db_value(self, value, *args, **kwargs):
        if isinstance(value, memoryview):
            value = value.tobytes()
        if isinstance(value, six.binary_type):
            return value.decode(self._encoding, errors=self._encoding_errors)
        else:
            return value

    def get_db_prep_value(self, value, connection, prepared=False):
        value = super(CharField, self).get_db_prep_value(
            value, connection, prepared)
        if value == '':
            return b''
        elif value is None:
            return None
        else:
            return acra.create_acra_struct(value.encode(self._encoding), self._public_key)

    def get_internal_type(self):
        return 'BinaryField'

    def to_python(self, value):
        value = super(CharField, self).to_python(value)
        if isinstance(value, six.binary_type):
            return value.decode(self._encoding, errors=self._encoding_errors)
        else:
            return value


class EmailField(CharField):
    default_validators = [validators.validate_email]
    description = _("Email address")

    def __init__(self, *args, **kwargs):
        kwargs['max_length'] = kwargs.get('max_length', 254)
        super(EmailField, self).__init__(*args, **kwargs)


class TextField(CharField):
    description = _("Text")

    def __init__(self, *args, **kwargs):
        super(TextField, self).__init__(*args, **kwargs)
        self.validators = []

    def formfield(self, **kwargs):
        # Passing max_length to forms.CharField means that the value's length
        # will be validated twice. This is considered acceptable since we want
        # the value in the form field (to pass into widget for example).
        defaults = {'max_length': self.max_length, 'widget': forms.Textarea}
        defaults.update(kwargs)
        return super(TextField, self).formfield(**defaults)

    def check(self, **kwargs):
        return []
