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

"""JWT claim extraction for identity propagation.

Provides lightweight helpers that decode a JWT payload **without
verification** (the token was already validated by the OIDC provider)
to extract claims like ``sub``, ``email``, and ``preferred_username``
for use as Kubernetes CRD annotations.
"""

from __future__ import annotations

import base64
import json


def extract_jwt_claims(token: str) -> dict:
    """Decode a JWT's payload WITHOUT verification (for claim extraction only).

    The token has already been validated by the OIDC provider.  This is
    purely for reading claims like sub, email, preferred_username, groups.

    Args:
        token: A JWT access token (three dot-separated base64url segments).

    Returns:
        The decoded payload as a dict.

    Raises:
        ValueError: If the token is not a valid JWT format.
    """
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    payload = parts[1]
    payload += "=" * (4 - len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def identity_annotations(token: str, prefix: str = "kubeflow.org") -> dict[str, str]:
    """Extract JWT claims and format as Kubernetes annotations.

    Args:
        token: A JWT access token.
        prefix: Annotation key prefix (default ``kubeflow.org``).

    Returns:
        Dict of annotation key-value pairs derived from JWT claims.
    """
    claims = extract_jwt_claims(token)
    annotations: dict[str, str] = {}
    if "sub" in claims:
        annotations[f"{prefix}/user-id"] = claims["sub"]
    if "email" in claims:
        annotations[f"{prefix}/user-email"] = claims["email"]
    if "preferred_username" in claims:
        annotations[f"{prefix}/user-name"] = claims["preferred_username"]
    if "groups" in claims:
        groups = claims["groups"]
        if isinstance(groups, list):
            annotations[f"{prefix}/user-groups"] = ",".join(str(g) for g in groups)
        else:
            annotations[f"{prefix}/user-groups"] = str(groups)
    return annotations
