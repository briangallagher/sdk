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

"""Tests for JWT identity extraction."""

from __future__ import annotations

import base64
import json

import pytest

from kubeflow.common.auth.identity import extract_jwt_claims, identity_annotations


def _make_jwt(payload: dict) -> str:
    """Build a fake JWT (header.payload.signature) with the given payload."""
    header = base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode()).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(b"fake-signature").rstrip(b"=").decode()
    return f"{header}.{body}.{sig}"


class TestExtractJwtClaims:
    def test_extracts_all_claims(self):
        payload = {
            "sub": "user-123",
            "email": "user@example.com",
            "preferred_username": "testuser",
            "groups": ["admin", "dev"],
            "iss": "https://idp.example.com",
        }
        token = _make_jwt(payload)
        claims = extract_jwt_claims(token)
        assert claims["sub"] == "user-123"
        assert claims["email"] == "user@example.com"
        assert claims["preferred_username"] == "testuser"
        assert claims["groups"] == ["admin", "dev"]
        assert claims["iss"] == "https://idp.example.com"

    def test_invalid_jwt_format_raises(self):
        with pytest.raises(ValueError, match="Invalid JWT format"):
            extract_jwt_claims("not-a-jwt")

    def test_two_parts_raises(self):
        with pytest.raises(ValueError, match="Invalid JWT format"):
            extract_jwt_claims("header.payload")

    def test_empty_payload(self):
        token = _make_jwt({})
        claims = extract_jwt_claims(token)
        assert claims == {}


class TestIdentityAnnotations:
    def test_all_fields_present(self):
        payload = {
            "sub": "user-123",
            "email": "user@example.com",
            "preferred_username": "testuser",
        }
        token = _make_jwt(payload)
        annotations = identity_annotations(token)
        assert annotations == {
            "kubeflow.org/user-id": "user-123",
            "kubeflow.org/user-email": "user@example.com",
            "kubeflow.org/user-name": "testuser",
        }

    def test_custom_prefix(self):
        token = _make_jwt({"sub": "abc"})
        annotations = identity_annotations(token, prefix="myorg.io")
        assert annotations == {"myorg.io/user-id": "abc"}

    def test_partial_claims(self):
        token = _make_jwt({"sub": "abc"})
        annotations = identity_annotations(token)
        assert "kubeflow.org/user-id" in annotations
        assert "kubeflow.org/user-email" not in annotations
        assert "kubeflow.org/user-name" not in annotations

    def test_no_relevant_claims(self):
        token = _make_jwt({"iss": "https://idp.example.com"})
        annotations = identity_annotations(token)
        assert annotations == {}

    def test_groups_list(self):
        token = _make_jwt({"sub": "u1", "groups": ["admin", "dev"]})
        annotations = identity_annotations(token)
        assert annotations["kubeflow.org/user-groups"] == "admin,dev"

    def test_groups_string(self):
        token = _make_jwt({"sub": "u1", "groups": "single"})
        annotations = identity_annotations(token)
        assert annotations["kubeflow.org/user-groups"] == "single"
