#!/usr/bin/python3
# coding=utf-8

#   Copyright 2026 EPAM Systems
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import base64


def fs_encode_name(name, kind=None, encoder=None):
    """ Name encoder """
    if encoder == "base64":
        return base64.urlsafe_b64encode(name.encode()).decode()
    #
    if encoder == "base32":
        return base64.b32encode(name.encode()).decode()
    #
    if encoder == "azureblob":
        if kind == "bucket":
            if name.startswith("p--"):
                return name.replace("p--", "p.", 1).replace(".", "-", 2)
    #
    return name


def fs_decode_name(name, kind=None, encoder=None):
    """ Name decoder """
    if encoder == "base64":
        return base64.urlsafe_b64decode(name.encode()).decode()
    #
    if encoder == "base32":
        return base64.b32decode(name.encode()).decode()
    #
    if encoder == "azureblob":
        if kind == "bucket":
            if name.startswith("p-") and not name.startswith("p--"):
                return name.replace("-", ".", 2).replace("p.", "p--", 1)
    #
    return name
