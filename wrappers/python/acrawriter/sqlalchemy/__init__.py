# Copyright 2018, Cossack Labs Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# coding: utf-8

from sqlalchemy import types
from acrawriter import create_acrastruct


__all__ = ('AcraBinary', 'AcraString')


class AcraBinary(types.TypeDecorator):
    impl = types.LargeBinary

    def __init__(self, public_key, *args, **kwargs):
        super(AcraBinary, self).__init__(*args, **kwargs)
        self._public_key = public_key

    def process_bind_param(self, value, dialect):
        return create_acrastruct(value, self._public_key)

    def process_result_value(self, value, dialect):
        return value


class AcraString(AcraBinary):
    def __init__(self, public_key, encoding='utf-8', *args, **kwargs):
        super(AcraString, self).__init__(public_key, *args, **kwargs)
        self._encoding = encoding

    def process_bind_param(self, value, dialect):
        return super(AcraString, self).process_bind_param(
            value.encode(self._encoding), dialect)

    def process_result_value(self, value, dialect):
        if isinstance(value, str):
            return value
        else:
            return value.decode(self._encoding)
