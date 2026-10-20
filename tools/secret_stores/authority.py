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

""" Store authority: the only way to obtain a context a SecretStore accepts """

import re
import uuid

_SEAL = object()  # module-private: only CredentialStoreProvider.mint holds it

PURPOSES = frozenset({"onboard", "probe", "retire", "reconcile", "smoke"})

# operation -> purposes allowed to perform it ("release" is added by WP-1D only)
OPERATION_PURPOSES = {
    "read": frozenset({"probe", "reconcile", "smoke"}),
    "write": frozenset({"onboard"}),
    "metadata": frozenset({"probe", "reconcile", "smoke"}),
    "delete_all": frozenset({"retire", "reconcile"}),
}

# decision_id goes into a request header: keep it to a safe token alphabet
_DECISION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class AuthorizedStoreContext:
    """ Proof that a caller made (and audited) a decision for one store operation """

    __slots__ = ("purpose", "decision_id", "actor_ref", "project_id", "ref_id")

    def __init__(self, *, _seal=None, purpose, decision_id, actor_ref, project_id, ref_id):
        if _seal is not _SEAL:
            raise TypeError("AuthorizedStoreContext is not constructible")
        for name, value in (
                ("purpose", purpose), ("decision_id", decision_id),
                ("actor_ref", actor_ref), ("project_id", project_id), ("ref_id", ref_id),
        ):
            object.__setattr__(self, name, value)

    def __setattr__(self, name, value):
        raise AttributeError("AuthorizedStoreContext is immutable")

    def __delattr__(self, name):
        raise AttributeError("AuthorizedStoreContext is immutable")

    def __reduce__(self):
        raise TypeError("AuthorizedStoreContext cannot be copied or pickled")

    def __repr__(self):
        return f"AuthorizedStoreContext(purpose={self.purpose!r}, project_id={self.project_id})"

    __str__ = __repr__


class CredentialStoreProvider:  # pylint: disable=R0903
    """ The only minting point of AuthorizedStoreContext """

    @staticmethod
    def mint(purpose, *, decision_id, actor_ref, project_id, ref_id):
        """ Mint a context; decision_id is the event_id of the caller's audit event """
        if purpose not in PURPOSES:
            raise ValueError("unknown purpose")
        decision_id = str(decision_id)
        if not _DECISION_ID_RE.match(decision_id):
            raise ValueError("invalid decision_id")
        if not isinstance(actor_ref, str) or not actor_ref:
            raise ValueError("invalid actor_ref")
        if isinstance(project_id, bool) or not isinstance(project_id, int):
            raise ValueError("invalid project_id")
        if not isinstance(ref_id, uuid.UUID):
            raise ValueError("invalid ref_id")
        return AuthorizedStoreContext(
            _seal=_SEAL, purpose=purpose, decision_id=decision_id,
            actor_ref=actor_ref, project_id=project_id, ref_id=ref_id,
        )

