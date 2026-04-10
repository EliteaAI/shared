#!/usr/bin/python
# coding=utf-8

#     Copyright 2026 EPAM Systems
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

""" Secrets DB model """

from sqlalchemy import Column, Text, LargeBinary  # pylint: disable=E0401

from ..tools import db, db_tools


class SecretsKey(db_tools.AbstractBaseMixin, db.Base):  # pylint: disable=C0111
    __tablename__ = "secrets_key"

    id = Column(Text, primary_key=True)
    data = Column(LargeBinary, unique=False)

    @property
    def serialized(self):
        raise RuntimeError("Not supported")


class SecretsData(db_tools.AbstractBaseMixin, db.Base):  # pylint: disable=C0111
    __tablename__ = "secrets_data"

    id = Column(Text, primary_key=True)
    data = Column(LargeBinary, unique=False)

    @property
    def serialized(self):
        raise RuntimeError("Not supported")
