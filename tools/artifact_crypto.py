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

""" Authenticated encryption for platform-produced artifacts

An artifact (project backup, chat export, ...) is wrapped in a framed
AES-256-GCM envelope keyed from SECRETS_MASTER_KEY, so it can only be read
back on a setup holding the same master key. Every artifact kind has its own
magic and HKDF info strings: keys are domain separated, so an artifact of one
kind can never be accepted as another.

Envelope layout (frames keep the stream constant-memory for any size):

    <MAGIC>\\n
    {"v":1,"cipher":...,"salt":...,"key_id":...,"frame_size":...}\\n
    <4-byte length><1-byte final flag><ciphertext+tag>
    ...

The per-frame AAD is the header bytes plus (index, final flag): that binds
every frame to the declared parameters, to its position in the stream and to
the end of it, so frames can not be reordered, dropped, spliced in from
another artifact, or the stream cut short unnoticed.
"""

import os
import json
import base64
import struct

from cryptography.exceptions import InvalidTag  # pylint: disable=E0401
from cryptography.hazmat.primitives import hashes  # pylint: disable=E0401
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # pylint: disable=E0401
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # pylint: disable=E0401

from pylon.core.tools import log  # pylint: disable=E0611,E0401


ENVELOPE_SUFFIX = ".enc"
ENVELOPE_MIMETYPE = "application/octet-stream"

CIPHER = "AES-256-GCM"
KDF = "HKDF-SHA256"

SALT_BYTES = 16
KEY_BYTES = 32
TAG_BYTES = 16
KEY_ID_BYTES = 8

FRAME_SIZE = 1048576
MAX_FRAME_SIZE = 8388608
MAX_HEADER_BYTES = 8192

FRAME_HEADER = struct.Struct(">IB")
FRAME_AAD = struct.Struct(">QB")

# Not "on"/"off": YAML reads those as booleans, and a policy silently dropped
# because it arrived as False would fail open
POLICY_DISABLED = "disabled"
POLICY_ENABLED = "enabled"
POLICY_REQUIRED = "required"
POLICIES = (POLICY_DISABLED, POLICY_ENABLED, POLICY_REQUIRED)


class EnvelopeKeyMismatch(ValueError):
    """ Artifact is a valid envelope, but was encrypted for another setup """


class EnvelopeIntegrityError(ValueError):
    """ Artifact is malformed, truncated, modified or not an envelope at all """


def configured_master_key():
    """ SECRETS_MASTER_KEY as bytes, or None when the setup has none """
    from tools import config as pylon_config  # pylint: disable=E0401,C0415
    #
    value = getattr(pylon_config, "SECRETS_MASTER_KEY", None)
    if not value:
        return None
    #
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8")


def resolve_policy(config, config_key):
    """ Read an encryption policy out of a plugin descriptor config """
    value = (config or {}).get(config_key)
    #
    if value is None:
        return POLICY_ENABLED
    #
    # A YAML "off"/"no" arrives as a bool, so it is honoured explicitly instead
    # of falling through to the default
    if isinstance(value, bool):
        return POLICY_ENABLED if value else POLICY_DISABLED
    #
    value = str(value).strip().lower()
    if value in POLICIES:
        return value
    #
    log.warning(
        "artifact_crypto: unknown %s value %r, using %s", config_key, value, POLICY_ENABLED,
    )
    return POLICY_ENABLED


def _nonce(index):
    """ Counter nonce: the salt makes the frame key unique per artifact, so an
        index that restarts at 0 can not repeat a (key, nonce) pair """
    return b"\x00\x00\x00\x00" + struct.pack(">Q", index)


class _Reader:
    """ read/read_line over an iterator of byte chunks """

    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self._buffer = bytearray()
        self._eof = False

    def _fill(self, size):
        while len(self._buffer) < size and not self._eof:
            try:
                self._buffer += next(self._chunks)
            except StopIteration:
                self._eof = True

    def read(self, size):
        """ Up to size bytes; a short result means the stream ended """
        self._fill(size)
        data = bytes(self._buffer[:size])
        del self._buffer[:size]
        return data

    def read_line(self, limit, error):
        """ One newline-terminated line, newline stripped """
        while True:
            position = self._buffer.find(b"\n")
            if position >= 0:
                line = bytes(self._buffer[:position])
                del self._buffer[:position + 1]
                return line
            #
            if self._eof or len(self._buffer) > limit:
                raise EnvelopeIntegrityError(error)
            #
            self._fill(len(self._buffer) + 4096)

    def at_eof(self):
        self._fill(1)
        return not self._buffer


class Envelope:  # pylint: disable=R0902
    """ Envelope for one artifact kind """

    def __init__(self, magic, key_info, key_id_info, label):
        # The frame key and the fingerprint are derived from the same master
        # key and must never coincide
        if key_info == key_id_info:
            raise ValueError("key_info and key_id_info must differ")
        #
        self.magic = magic
        self.key_info = key_info
        self.key_id_info = key_id_info
        self.label = label
        #
        title = label[:1].upper() + label[1:]
        self.msg_header = "Malformed {} envelope header".format(label)
        self.msg_not_envelope = "Not an ELITEA encrypted {}".format(label)
        self.msg_other_setup = "This {} was encrypted for another setup.".format(label)
        self.msg_truncated = "{} file is truncated".format(title)
        self.msg_malformed = "{} file is malformed".format(title)
        self.msg_tag = (
            "{} file failed its integrity check: it was not produced by this"
            " platform, was encrypted with another key, or has been modified"
        ).format(title)
        self.msg_trailing = "{} file has trailing data after its last frame".format(title)

    def key_id(self, master_key):
        """ Fingerprint of the master key

        Lets a reader tell "encrypted for another setup" from "corrupted file".
        Derived through the KDF, so it carries nothing usable back to the key.
        """
        return HKDF(
            algorithm=hashes.SHA256(), length=KEY_ID_BYTES, salt=b"", info=self.key_id_info,
        ).derive(master_key).hex()

    def _frame_key(self, master_key, salt):
        return HKDF(
            algorithm=hashes.SHA256(), length=KEY_BYTES, salt=salt, info=self.key_info,
        ).derive(master_key)

    def _pack_header(self, salt, fingerprint, frame_size):
        header = {
            "v": 1,
            "cipher": CIPHER,
            "kdf": KDF,
            "salt": base64.b64encode(salt).decode("ascii"),
            "key_id": fingerprint,
            "frame_size": frame_size,
        }
        return b"".join((
            self.magic, b"\n",
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8"), b"\n",
        ))

    @staticmethod
    def _pack_frame(cipher, header, index, payload, final):
        flag = 1 if final else 0
        data = cipher.encrypt(_nonce(index), payload, header + FRAME_AAD.pack(index, flag))
        return FRAME_HEADER.pack(len(data), flag) + data

    def is_encrypted(self, head):
        """ True if an artifact starts with the envelope magic """
        if isinstance(head, str):
            head = head.encode("utf-8", "replace")
        return head.startswith(self.magic)

    def iter_encrypt(self, chunks, master_key, frame_size=FRAME_SIZE):
        """ Wrap a stream of bytes into the envelope """
        salt = os.urandom(SALT_BYTES)
        header = self._pack_header(salt, self.key_id(master_key), frame_size)
        yield header
        #
        cipher = AESGCM(self._frame_key(master_key, salt))
        buffer = bytearray()
        index = 0
        #
        for chunk in chunks:
            buffer += chunk
            # Strictly greater: a full buffer with nothing behind it may still be
            # the last frame, and only the final one carries the end-of-stream flag
            while len(buffer) > frame_size:
                yield self._pack_frame(cipher, header, index, bytes(buffer[:frame_size]), False)
                del buffer[:frame_size]
                index += 1
        #
        yield self._pack_frame(cipher, header, index, bytes(buffer), True)

    def _read_header(self, reader):
        """ Parse and validate the envelope header, returning its exact bytes too """
        magic = reader.read_line(len(self.magic) + 2, self.msg_header)
        if magic != self.magic:
            raise EnvelopeIntegrityError(self.msg_not_envelope)
        #
        line = reader.read_line(MAX_HEADER_BYTES, self.msg_header)
        #
        try:
            header = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise EnvelopeIntegrityError(self.msg_header) from exc
        #
        if not isinstance(header, dict):
            raise EnvelopeIntegrityError(self.msg_header)
        #
        if header.get("v") != 1 or header.get("cipher") != CIPHER or header.get("kdf") != KDF:
            raise EnvelopeIntegrityError(
                "Unsupported {} envelope (v={}, cipher={})".format(
                    self.label, header.get("v"), header.get("cipher"),
                )
            )
        #
        frame_size = header.get("frame_size")
        if not isinstance(frame_size, int) or isinstance(frame_size, bool) \
                or not 0 < frame_size <= MAX_FRAME_SIZE:
            raise EnvelopeIntegrityError(self.msg_header)
        #
        try:
            salt = base64.b64decode(str(header.get("salt") or ""), validate=True)
        except (ValueError, TypeError) as exc:
            raise EnvelopeIntegrityError(self.msg_header) from exc
        #
        if len(salt) != SALT_BYTES or not isinstance(header.get("key_id"), str):
            raise EnvelopeIntegrityError(self.msg_header)
        #
        return magic + b"\n" + line + b"\n", header, salt, frame_size

    def iter_decrypt(self, chunks, master_key):
        """ Unwrap the envelope, verifying every frame """
        reader = _Reader(chunks)
        header_bytes, header, salt, frame_size = self._read_header(reader)
        #
        if header["key_id"] != self.key_id(master_key):
            raise EnvelopeKeyMismatch(self.msg_other_setup)
        #
        cipher = AESGCM(self._frame_key(master_key, salt))
        limit = frame_size + TAG_BYTES
        index = 0
        #
        while True:
            prefix = reader.read(FRAME_HEADER.size)
            if len(prefix) < FRAME_HEADER.size:
                raise EnvelopeIntegrityError(self.msg_truncated)
            #
            length, flag = FRAME_HEADER.unpack(prefix)
            if flag not in (0, 1) or not TAG_BYTES <= length <= limit:
                raise EnvelopeIntegrityError(self.msg_malformed)
            #
            data = reader.read(length)
            if len(data) < length:
                raise EnvelopeIntegrityError(self.msg_truncated)
            #
            try:
                payload = cipher.decrypt(
                    _nonce(index), data, header_bytes + FRAME_AAD.pack(index, flag),
                )
            except InvalidTag as exc:
                raise EnvelopeIntegrityError(self.msg_tag) from exc
            #
            if payload:
                yield payload
            #
            if flag:
                break
            #
            index += 1
        #
        if not reader.at_eof():
            raise EnvelopeIntegrityError(self.msg_trailing)

    def wrap_decrypt(self, open_bytes, master_key):
        """ Turn a byte-chunk opener into one yielding the decrypted artifact """
        def opener():
            return self.iter_decrypt(open_bytes(), master_key)
        #
        return opener
