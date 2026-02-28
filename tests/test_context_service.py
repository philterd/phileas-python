# Copyright 2026 Philterd, LLC
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

"""Tests for the ContextService implementations."""

import pytest

from phileas.services.context import AbstractContextService, InMemoryContextService


class TestInMemoryContextService:
    def test_put_and_get(self):
        svc = InMemoryContextService()
        svc.put("ctx1", "John Smith", "PERSON-1")
        assert svc.get("ctx1", "John Smith") == "PERSON-1"

    def test_get_missing_token_returns_none(self):
        svc = InMemoryContextService()
        assert svc.get("ctx1", "unknown") is None

    def test_get_missing_context_returns_none(self):
        svc = InMemoryContextService()
        assert svc.get("nonexistent", "token") is None

    def test_contains_existing_token(self):
        svc = InMemoryContextService()
        svc.put("ctx1", "555-12-3456", "XXX-XX-XXXX")
        assert svc.contains("ctx1", "555-12-3456") is True

    def test_contains_missing_token(self):
        svc = InMemoryContextService()
        assert svc.contains("ctx1", "missing") is False

    def test_contains_missing_context(self):
        svc = InMemoryContextService()
        assert svc.contains("nonexistent", "token") is False

    def test_multiple_contexts_isolated(self):
        svc = InMemoryContextService()
        svc.put("ctx1", "token", "replacement-A")
        svc.put("ctx2", "token", "replacement-B")
        assert svc.get("ctx1", "token") == "replacement-A"
        assert svc.get("ctx2", "token") == "replacement-B"

    def test_overwrite_replacement(self):
        svc = InMemoryContextService()
        svc.put("ctx1", "token", "first")
        svc.put("ctx1", "token", "second")
        assert svc.get("ctx1", "token") == "second"

    def test_multiple_tokens_in_same_context(self):
        svc = InMemoryContextService()
        svc.put("ctx1", "token-A", "rep-A")
        svc.put("ctx1", "token-B", "rep-B")
        assert svc.get("ctx1", "token-A") == "rep-A"
        assert svc.get("ctx1", "token-B") == "rep-B"

    def test_is_abstract_base_instance(self):
        svc = InMemoryContextService()
        assert isinstance(svc, AbstractContextService)

    def test_custom_context_service(self):
        """Users can provide their own implementation."""
        class CustomContextService(AbstractContextService):
            def __init__(self):
                self._data = {}

            def put(self, context, token, replacement):
                self._data[(context, token)] = replacement

            def get(self, context, token):
                return self._data.get((context, token))

            def contains(self, context, token):
                return (context, token) in self._data

        svc = CustomContextService()
        svc.put("ctx", "tok", "rep")
        assert svc.get("ctx", "tok") == "rep"
        assert svc.contains("ctx", "tok") is True
        assert svc.contains("ctx", "other") is False
