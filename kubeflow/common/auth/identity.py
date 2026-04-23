# Copyright 2025 The Kubeflow Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Identity helpers for extracting user information from JWT tokens."""

from __future__ import annotations

import base64
import json
import logging

logger = logging.getLogger(__name__)

_ANNOTATION_PREFIX = "kubeflow.org/"

_CLAIM_MAP = {
    "sub": "user-id",
    "email": "user-email",
    "preferred_username": "user-name",
    "groups": "user-groups",
}


def identity_annotations(token: str) -> dict[str, str]:
    """Extract Kubernetes annotations from JWT claims.

    Decodes the JWT payload (without signature verification -- the API server
    already validated the token) and maps standard OIDC claims to
    ``kubeflow.org/`` annotations suitable for setting on Jobs/Pods.

    Returns an empty dict if the token cannot be decoded.
    """
    try:
        payload = _decode_jwt_payload(token)
    except Exception:
        logger.debug("Could not decode JWT payload for identity annotations")
        return {}

    annotations: dict[str, str] = {}
    for claim, annotation_suffix in _CLAIM_MAP.items():
        value = payload.get(claim)
        if value is None:
            continue
        if isinstance(value, list):
            value = ",".join(str(v) for v in value)
        annotations[f"{_ANNOTATION_PREFIX}{annotation_suffix}"] = str(value)

    return annotations


def _decode_jwt_payload(token: str) -> dict:
    """Decode JWT payload without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Not a valid JWT (expected 3 dot-separated parts)")

    payload_b64 = parts[1]
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding

    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)
