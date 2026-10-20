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

""" SecretStore adapter over the database secret engine (own section, unreachable by templates) """

from ..secret_engines.database import Engine, SectionCheckFailed

from . import SecretMetadata, SecretValue, StoreError, check_context

SECTION = "credential_store"  # not merged by {{secret.*}} resolution or the reveal routes


def _prefix(ref):
    return f"{ref.ref_id.hex}:"


def _versions(section, ref):
    prefix = _prefix(ref)
    found = set()
    for key in section:
        head, _, tail = key.partition(":")
        if f"{head}:" == prefix and tail.isdigit():
            found.add(int(tail))
    return found


class DatabaseSecretStore:
    """ Material is {field: value} under key '<ref_id.hex>:<generation>' of the credential_store section """

    @staticmethod
    def _engine(ref):
        # fresh engine per call: no cross-call cache; dict form avoids the project RPC
        return Engine(project={"id": ref.project_id})

    def read(self, ref, generation, ctx):
        check_context(ctx, ref, "read")
        try:
            section = self._engine(ref)._read().get(SECTION, {})  # pylint: disable=W0212
            bundle = section.get(f"{_prefix(ref)}{int(generation)}")
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
        if bundle is None:
            raise StoreError("NOT_FOUND")
        return SecretValue(bundle, int(generation))

    def write(self, ref, value, *, expected_version, ctx):
        check_context(ctx, ref, "write")
        generation = int(expected_version) + 1
        bundle = {name: secret.get_secret_value() for name, secret in value.fields.items()}
        try:
            self._engine(ref)._update_section(  # pylint: disable=W0212
                SECTION,
                add={f"{_prefix(ref)}{generation}": bundle},
                check=lambda current: max(_versions(current, ref), default=0) == expected_version,
            )
        except SectionCheckFailed:
            raise StoreError("VERSION_CONFLICT") from None
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
        return SecretMetadata(current_version=generation, versions=frozenset({generation}))

    def metadata(self, ref, ctx):
        check_context(ctx, ref, "metadata")
        try:
            found = _versions(self._engine(ref)._read().get(SECTION, {}), ref)  # pylint: disable=W0212
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
        return SecretMetadata(current_version=max(found, default=0), versions=frozenset(found))

    def delete_all(self, ref, ctx):
        check_context(ctx, ref, "delete_all")
        try:
            engine = self._engine(ref)
            keys = [f"{_prefix(ref)}{n}" for n in _versions(engine._read().get(SECTION, {}), ref)]  # pylint: disable=W0212
            if keys:
                engine._update_section(SECTION, remove=keys)  # pylint: disable=W0212
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
