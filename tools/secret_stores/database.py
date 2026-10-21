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

""" SecretStore adapter over the database secret engine.

Material lives in its OWN encrypted row ('<project db key>:cs' of secrets_data, same project key), so the
legacy {{secret.*}} paths never decrypt it and a governed read never decrypts legacy secrets (C-1009 S10).

Migration: the FIRST governed operation on a project (read, read_many, metadata, write, prune or delete_all)
moves a pre-split 'credential_store' section out of the legacy blob into the new row, in one transaction
under the legacy row lock. A read therefore does a one-time write for an unmigrated project; every later
call is a single read of the new row. Deploy constraint: see secret_engines/database.py.
"""

from collections import defaultdict

from tools import context  # pylint: disable=E0401

from ..secret_engines.database import Engine, SectionCheckFailed

from . import SecretMetadata, SecretValue, StoreError, check_context, plan_read_many


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
    """ Material is {field: value} under key '<ref_id.hex>:<generation>' of the project's credential-store row """

    @staticmethod
    def _engine(project_id):
        # fresh engine per call: no cross-call cache; dict form avoids the project RPC
        return Engine(project={"id": project_id})

    def read(self, ref, generation, ctx):
        return self.read_many([ref], [generation], ctx)[(ref.ref_id, int(generation))]

    def read_many(self, refs, generations, ctx):
        """ One session and one blob decrypt per project in the call (normally one project) """
        planned = plan_read_many(refs, generations, ctx)
        if not planned:
            return {}
        projects = defaultdict(list)
        for ref, generation, _ in planned:
            projects[ref.project_id].append((ref, generation))
        try:
            sections = {}
            with context.db.make_session() as session:
                for project_id in projects:
                    sections[project_id] = self._engine(project_id)._read_governed(session)  # pylint: disable=W0212
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
        found = {}
        for project_id, items in projects.items():
            for ref, generation in items:
                bundle = sections[project_id].get(f"{_prefix(ref)}{generation}")
                if bundle is None:
                    raise StoreError("NOT_FOUND", {"ref_id": str(ref.ref_id)})
                found[(ref.ref_id, generation)] = SecretValue(bundle, generation)
        return found

    def write(self, ref, value, *, expected_version, ctx):
        check_context(ctx, ref, "write")
        generation = int(expected_version) + 1
        bundle = {name: secret.get_secret_value() for name, secret in value.fields.items()}
        #
        def mutate(section):
            if max(_versions(section, ref), default=0) != expected_version:
                raise SectionCheckFailed(ref.ref_id)
            section[f"{_prefix(ref)}{generation}"] = bundle
        #
        try:
            self._engine(ref.project_id)._update_governed(mutate)  # pylint: disable=W0212
        except SectionCheckFailed:
            raise StoreError("VERSION_CONFLICT") from None
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
        return SecretMetadata(current_version=generation, versions=frozenset({generation}))

    def metadata(self, ref, ctx):
        check_context(ctx, ref, "metadata")
        try:
            found = _versions(self._engine(ref.project_id)._read_governed(), ref)  # pylint: disable=W0212
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
        return SecretMetadata(current_version=max(found, default=0), versions=frozenset(found))

    def prune(self, ref, keep_generations, ctx):
        """ Keep the newest keep_generations (>= 1) generations of the reference, drop the rest """
        check_context(ctx, ref, "prune")
        if isinstance(keep_generations, bool) or not isinstance(keep_generations, int) or keep_generations < 1:
            raise ValueError("keep_generations must be an integer >= 1")
        remaining = {}
        #
        def mutate(section):
            found = sorted(_versions(section, ref))
            for generation in found[:-keep_generations]:
                section.pop(f"{_prefix(ref)}{generation}", None)
            remaining["versions"] = frozenset(found[-keep_generations:])
        #
        try:
            self._engine(ref.project_id)._update_governed(mutate)  # pylint: disable=W0212
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
        versions = remaining["versions"]
        return SecretMetadata(current_version=max(versions, default=0), versions=versions)

    def delete_all(self, ref, ctx):
        check_context(ctx, ref, "delete_all")
        #
        def mutate(section):
            for generation in _versions(section, ref):
                section.pop(f"{_prefix(ref)}{generation}", None)
        #
        try:
            self._engine(ref.project_id)._update_governed(mutate)  # pylint: disable=W0212
        except Exception:  # pylint: disable=W0703
            raise StoreError("UNAVAILABLE") from None
