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

"""The MAP_REPLACE strategy and the generators block."""

import io
import json

import pytest

from phileas.policy import map_replace as mr
from phileas.policy.generators import GeneratorError, OllamaGenerator, build_generator
from phileas.policy.map_replace import MapReplaceResolver
from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService


@pytest.fixture(autouse=True)
def _clear_file_cache():
    mr._FILE_CACHE.clear()
    yield
    mr._FILE_CACHE.clear()


class FakeGenerator:
    """Stands in for a local model: the contract is tested, not generated text."""

    def __init__(self, value=None, error=None):
        self.name = "fake"
        self.value = value
        self.error = error
        self.calls = []

    def generate(self, token, label=""):
        self.calls.append((token, label))
        if self.error is not None:
            raise self.error
        return self.value


def resolver(config, generator=None, contains_pii=None):
    r = MapReplaceResolver(config, None, contains_pii)
    r.generator = generator
    return r


def run(identifiers, text, context="c", generators=None):
    data = {"name": "t", "identifiers": identifiers}
    if generators:
        data["generators"] = generators
    return FilterService().filter(Policy.from_dict(data), context, "d", text)


def business(strategy, terms=("Jon's Shop",)):
    return {"dictionaries": [{"classification": "business", "terms": list(terms),
                              "customFilterStrategies": [strategy]}]}


class TestLookupTable:
    def test_map_hit(self):
        r = resolver({"mappings": {"jon's shop": "Joe's Shop"}})
        assert r.resolve("Jon's Shop") == "Joe's Shop"

    def test_map_miss_returns_none(self):
        assert resolver({"mappings": {"a": "b"}}).resolve("zzz") is None

    def test_case_insensitive_by_default(self):
        r = resolver({"mappings": {"JON": "Joe"}})
        assert r.resolve("jon") == "Joe"
        assert r.resolve("Jon") == "Joe"

    def test_case_sensitive_when_asked(self):
        r = resolver({"caseSensitive": True, "mappings": {"JON": "Joe"}})
        assert r.resolve("JON") == "Joe"
        assert r.resolve("jon") is None

    def test_key_and_token_normalisation_are_identical(self):
        r = resolver({"mappings": {"MiXeD CaSe": "x"}})
        assert r.resolve("mixed case") == "x"


class TestMappingFiles:
    def _write(self, tmp_path, name, rows):
        path = tmp_path / name
        path.write_text("".join(f"{k}\t{v}\n" for k, v in rows), encoding="utf-8")
        return str(path)

    def test_file_is_loaded(self, tmp_path):
        path = self._write(tmp_path, "a.tsv", [("jon", "Joe"), ("ann", "Amy")])
        r = resolver({"mappingFiles": [path]})
        assert r.resolve("Jon") == "Joe"
        assert r.resolve("ANN") == "Amy"

    def test_blank_and_malformed_rows_are_skipped(self, tmp_path):
        path = tmp_path / "b.tsv"
        path.write_text("jon\tJoe\n\nno-tab-here\n\nann\tAmy\n", encoding="utf-8")
        r = resolver({"mappingFiles": [str(path)]})
        assert r.mappings == {"jon": "Joe", "ann": "Amy"}

    def test_value_may_contain_tabs(self, tmp_path):
        path = tmp_path / "c.tsv"
        path.write_text("jon\tJoe\tExtra\n", encoding="utf-8")
        assert resolver({"mappingFiles": [str(path)]}).resolve("jon") == "Joe\tExtra"

    def test_inline_overrides_a_file(self, tmp_path):
        path = self._write(tmp_path, "d.tsv", [("jon", "FromFile")])
        r = resolver({"mappingFiles": [path], "mappings": {"jon": "Inline"}})
        assert r.resolve("jon") == "Inline"

    def test_a_later_file_overrides_an_earlier_one(self, tmp_path):
        first = self._write(tmp_path, "e1.tsv", [("jon", "First")])
        second = self._write(tmp_path, "e2.tsv", [("jon", "Second")])
        assert resolver({"mappingFiles": [first, second]}).resolve("jon") == "Second"

    def test_a_missing_file_does_not_raise(self, tmp_path):
        r = resolver({"mappingFiles": [str(tmp_path / "nope.tsv")], "mappings": {"a": "b"}})
        assert r.resolve("a") == "b"

    def test_file_is_read_once(self, tmp_path, monkeypatch):
        path = self._write(tmp_path, "f.tsv", [("jon", "Joe")])
        resolver({"mappingFiles": [path]})
        opened = []
        real_open = open
        monkeypatch.setattr("builtins.open", lambda *a, **k: opened.append(a[0]) or real_open(*a, **k))
        resolver({"mappingFiles": [path]})
        assert opened == []


class TestGenerator:
    def test_miss_calls_the_generator(self):
        gen = FakeGenerator(value="Joe's Shop")
        r = resolver({"mappings": {}}, gen)
        assert r.resolve("Jon's Shop", "business") == "Joe's Shop"
        assert gen.calls == [("Jon's Shop", "business")]

    def test_a_map_hit_does_not_call_the_generator(self):
        gen = FakeGenerator(value="Generated")
        r = resolver({"mappings": {"jon": "Mapped"}}, gen)
        assert r.resolve("Jon") == "Mapped"
        assert gen.calls == []

    def test_generator_failure_falls_back(self):
        r = resolver({}, FakeGenerator(error=GeneratorError("boom")))
        assert r.resolve("Jon") is None

    @pytest.mark.parametrize("value", ["", "   ", "\n"])
    def test_blank_output_is_rejected(self, value):
        assert resolver({}, FakeGenerator(value=value)).resolve("Jon") is None

    @pytest.mark.parametrize("value", ["Jon", "jon", "  JON  "])
    def test_output_equal_to_input_is_rejected(self, value):
        assert resolver({}, FakeGenerator(value=value)).resolve("Jon") is None

    def test_output_with_pii_is_rejected(self):
        r = resolver({}, FakeGenerator(value="call 555-123-4567"), contains_pii=lambda v: True)
        assert r.resolve("Jon") is None

    def test_output_without_pii_is_kept(self):
        r = resolver({}, FakeGenerator(value="Joe"), contains_pii=lambda v: False)
        assert r.resolve("Jon") == "Joe"

    def test_the_rescan_cannot_recurse(self):
        gen = FakeGenerator(value="Joe")
        seen = []

        def contains_pii(candidate):
            # Re-entering the resolver during validation must not call the generator.
            seen.append(r.resolve("Другой", "business"))
            return False

        r = resolver({}, gen, contains_pii)
        assert r.resolve("Jon", "business") == "Joe"
        assert seen == [None]
        assert gen.calls == [("Jon", "business")]


class TestCaching:
    def test_generator_runs_once_per_token_in_a_context(self):
        gen = FakeGenerator(value="Joe")
        r = resolver({}, gen)
        first = r.resolve("Jon", "business", "ctx")
        second = r.resolve("Jon", "business", "ctx")
        assert first == second == "Joe"
        assert len(gen.calls) == 1

    def test_a_different_context_resolves_again(self):
        gen = FakeGenerator(value="Joe")
        r = resolver({}, gen)
        r.resolve("Jon", "business", "one")
        r.resolve("Jon", "business", "two")
        assert len(gen.calls) == 2

    def test_repeated_value_in_one_document_is_replaced_consistently(self):
        out = run(
            business({"strategy": "MAP_REPLACE", "mappings": {"jon's shop": "Joe's Shop"}}),
            "Jon's Shop, then Jon's Shop again.",
        ).filtered_text
        assert out == "Joe's Shop, then Joe's Shop again."


class TestFallback:
    def test_default_fallback_is_redact(self):
        assert resolver({}).fallback == "REDACT"

    def test_fallback_is_honoured(self):
        out = run(business({"strategy": "MAP_REPLACE", "mappings": {},
                            "fallbackStrategy": "MASK"}), "Jon's Shop").filtered_text
        assert out == "*" * len("Jon's Shop")

    def test_map_replace_as_a_fallback_cannot_recurse(self):
        assert resolver({"fallbackStrategy": "MAP_REPLACE"}).fallback == "REDACT"

    def test_a_miss_is_never_left_in_the_clear(self):
        out = run(business({"strategy": "MAP_REPLACE", "mappings": {}}), "Jon's Shop").filtered_text
        assert "Jon's Shop" not in out
        assert "{{{REDACTED-business}}}" in out


class TestOllamaClient:
    def _generator(self, **overrides):
        config = {"type": "ollama", "endpoint": "http://localhost:11434/", "model": "llama3.1",
                  "prompt": "Rewrite {{token}} ({{label}}).", "timeoutMs": 250}
        config.update(overrides)
        return build_generator("g", config)

    def test_built_from_the_type_discriminator(self):
        assert isinstance(self._generator(), OllamaGenerator)

    def test_unknown_type_is_not_built(self):
        assert build_generator("g", {"type": "openai", "timeoutMs": 1}) is None
        assert build_generator("", {"type": "ollama"}) is None
        assert build_generator("g", None) is None

    def test_url_and_payload(self):
        gen = self._generator()
        assert gen.url == "http://localhost:11434/api/generate"
        payload = gen.payload("Jon's Shop", "business")
        assert payload == {"model": "llama3.1", "stream": False,
                           "prompt": "Rewrite Jon's Shop (business)."}

    def test_response_is_trimmed(self, monkeypatch):
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr("urllib.request.urlopen",
                            lambda *a, **k: Response(json.dumps({"response": "  Joe  \n"}).encode()))
        assert self._generator().generate("Jon") == "Joe"

    def test_the_timeout_is_passed_in_seconds(self, monkeypatch):
        seen = {}

        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(request, timeout=None):
            seen["timeout"] = timeout
            return Response(json.dumps({"response": "Joe"}).encode())

        monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
        self._generator(timeoutMs=250).generate("Jon")
        assert seen["timeout"] == 0.25

    def test_transport_failure_raises_generator_error(self, monkeypatch):
        def boom(*a, **k):
            raise TimeoutError("timed out")

        monkeypatch.setattr("urllib.request.urlopen", boom)
        with pytest.raises(GeneratorError):
            self._generator().generate("Jon")

    def test_a_response_without_a_value_raises(self, monkeypatch):
        class Response(io.BytesIO):
            def __enter__(self): return self
            def __exit__(self, *a): return False

        monkeypatch.setattr("urllib.request.urlopen",
                            lambda *a, **k: Response(json.dumps({"done": True}).encode()))
        with pytest.raises(GeneratorError):
            self._generator().generate("Jon")


class TestPolicyIntegration:
    def test_generators_block_round_trips(self):
        generators = {"g": {"type": "ollama", "endpoint": "http://localhost:11434",
                            "model": "m", "prompt": "{{token}}", "timeoutMs": 100}}
        policy = Policy.from_dict({"name": "p", "generators": generators})
        assert policy.generators == generators
        assert policy.to_dict()["generators"] == generators

    def test_an_unreachable_generator_falls_back(self):
        generators = {"g": {"type": "ollama", "endpoint": "http://127.0.0.1:9", "model": "m",
                            "prompt": "{{token}}", "timeoutMs": 50}}
        out = run(business({"strategy": "MAP_REPLACE", "mappings": {}, "generator": "g"}),
                  "Jon's Shop", generators=generators).filtered_text
        assert "Jon's Shop" not in out
        assert "{{{REDACTED-business}}}" in out

    def test_a_named_generator_that_is_absent_falls_back(self):
        out = run(business({"strategy": "MAP_REPLACE", "mappings": {}, "generator": "missing"}),
                  "Jon's Shop", generators={"other": {"type": "ollama", "timeoutMs": 1}}).filtered_text
        assert "{{{REDACTED-business}}}" in out

    def test_map_replace_is_a_registered_action(self):
        from phileas.actions import is_known

        assert is_known("MAP_REPLACE")


class TestSchema:
    def test_a_map_replace_policy_validates(self):
        jsonschema = pytest.importorskip("jsonschema")
        from phisql import policy_schema

        document = {
            "generators": {"g": {"type": "ollama", "endpoint": "http://localhost:11434",
                                 "model": "llama3.1", "prompt": "{{token}}", "timeoutMs": 2000}},
            "identifiers": {"ssn": {"ssnFilterStrategies": [{
                "strategy": "MAP_REPLACE", "mappings": {"a": "b"}, "mappingFiles": ["m.tsv"],
                "caseSensitive": True, "generator": "g", "fallbackStrategy": "REDACT"}]}},
        }
        jsonschema.validate(document, policy_schema.get_schema_dict())

    def test_a_generator_without_a_timeout_is_rejected(self):
        jsonschema = pytest.importorskip("jsonschema")
        from phisql import policy_schema

        document = {"generators": {"g": {"type": "ollama", "endpoint": "http://x",
                                         "model": "m", "prompt": "p"}}}
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(document, policy_schema.get_schema_dict())


class TestRescanIsLocal:
    """Validation must stay cheap and must never abort the document."""

    def _policy(self):
        return Policy.from_dict({"name": "p", "identifiers": {
            "pheyes": [{"endpoint": "http://127.0.0.1:9",
                        "phEyeFilterStrategies": [{"strategy": "REDACT"}]}],
            "emailAddress": {"emailAddressFilterStrategies": [{"strategy": "REDACT"}]}}})

    def test_rescan_does_not_call_ph_eye(self, monkeypatch):
        from phileas.filters.ph_eye_filter import PhEyeFilter

        calls = []
        monkeypatch.setattr(PhEyeFilter, "detect",
                            lambda self, text, context="default": calls.append(text) or [])
        spans = FilterService()._detect_only(self._policy(), "mail me at a@b.com")
        assert calls == []
        assert len(spans) == 1

    def test_a_failing_rescan_falls_back_rather_than_raising(self, monkeypatch):
        gen = FakeGenerator(value="Joe's Shop")
        monkeypatch.setattr(mr, "build_generator", lambda name, config: gen)
        monkeypatch.setattr(
            FilterService, "_detect_only",
            lambda self, policy, text: (_ for _ in ()).throw(OSError("endpoint down")),
        )
        generators = {"g": {"type": "ollama", "endpoint": "http://x", "model": "m",
                            "prompt": "p", "timeoutMs": 50}}
        out = run(business({"strategy": "MAP_REPLACE", "mappings": {}, "generator": "g"}),
                  "Visit Jon's Shop.", generators=generators).filtered_text
        assert "{{{REDACTED-business}}}" in out


class TestCachingAcrossDocuments:
    def _run_twice(self, monkeypatch):
        gen = FakeGenerator(value="Joe's Shop")
        monkeypatch.setattr(mr, "build_generator", lambda name, config: gen)
        generators = {"g": {"type": "ollama", "endpoint": "http://x", "model": "m",
                            "prompt": "p", "timeoutMs": 50}}
        identifiers = business({"strategy": "MAP_REPLACE", "mappings": {}, "generator": "g"})
        policy = Policy.from_dict({"name": "p", "identifiers": identifiers,
                                   "generators": generators})
        service = FilterService()
        first = service.filter(policy, "ctx", "one", "Visit Jon's Shop.").filtered_text
        second = service.filter(policy, "ctx", "two", "Jon's Shop again.").filtered_text
        third = service.filter(policy, "other", "three", "Jon's Shop elsewhere.").filtered_text
        return gen, first, second, third

    def test_generator_runs_once_per_context(self, monkeypatch):
        gen, first, second, _ = self._run_twice(monkeypatch)
        assert "Joe's Shop" in first and "Joe's Shop" in second
        assert [t for t, _ in gen.calls].count("Jon's Shop") == 2  # one per context

    def test_replacement_is_consistent_across_documents(self, monkeypatch):
        _, first, second, _ = self._run_twice(monkeypatch)
        assert first == "Visit Joe's Shop." and second == "Joe's Shop again."
