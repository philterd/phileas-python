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

"""
Integration tests: author a policy in PhiSQL, compile it with the ``phisql``
dependency, then execute the compiled Phileas JSON with phileas. This exercises
the contract that the catalog drives both projects identically.
"""

from phisql import Compiler

from phileas.policy.policy import Policy
from phileas.services.filter_service import FilterService


def compile_and_run(source, text, context="ctx"):
    policy_json = Compiler().compile(source).policy_json()
    policy = Policy.from_dict(policy_json)
    return FilterService().filter(policy, context, "doc", text)


class TestPhiSQLIntegration:
    def test_deidentify_multiple(self):
        src = """
        POLICY clinical;
        DEIDENTIFY
          SSN AS HASH_SHA256,
          EMAIL_ADDRESS AS REDACT,
          DATE AS SHIFT(days=10),
          CREDIT_CARD AS LAST_4;
        """
        text = "SSN 123-45-6789, email a@b.com, dob 01/05/2020, card 4111111111111111."
        out = compile_and_run(src, text).filtered_text
        assert "123-45-6789" not in out
        assert "{{{REDACTED-email-address}}}" in out
        assert "01/15/2020" in out          # SHIFT(days=10)
        assert "************1111" in out      # LAST_4

    def test_redact_with_condition_met(self):
        # PhiSQL compiles WHERE to the singular `condition` key; regex spans have
        # confidence 1.0, so this condition holds and the mask is applied.
        src = "POLICY p; REDACT SSN WITH MASK(mask_char='#') WHERE CONFIDENCE > 0.5;"
        out = compile_and_run(src, "SSN 123-45-6789.").filtered_text
        assert "###########" in out

    def test_redact_with_condition_not_met(self):
        # Proves phileas actually reads the compiled `condition`: a condition that
        # cannot hold (regex confidence is 1.0) leaves the value untouched.
        src = "POLICY p; REDACT SSN WITH MASK(mask_char='#') WHERE CONFIDENCE < 0.5;"
        out = compile_and_run(src, "SSN 123-45-6789.").filtered_text
        assert out == "SSN 123-45-6789."

    def test_compiler_emits_singular_condition_key(self):
        # Guard: the compiled JSON uses `condition`, not the deprecated `conditions`.
        policy_json = Compiler().compile(
            "POLICY p; REDACT SSN WITH REDACT WHERE CONFIDENCE > 0.5;").policy_json()
        strat = policy_json["identifiers"]["ssn"]["ssnFilterStrategies"][0]
        assert "condition" in strat
        assert "conditions" not in strat

    def test_custom_identifier(self):
        src = (
            "POLICY p; DEFINE IDENTIFIER 'MRN' MATCHING 'MRN-\\d{6}' "
            "CASE INSENSITIVE WITH REDACT(format='[{{MRN}}]');"
        )
        out = compile_and_run(src, "Record mrn-123456 today.").filtered_text
        assert "mrn-123456" not in out
        assert "[{{MRN}}]" in out

    def test_static_replace(self):
        src = "POLICY p; REDACT EMAIL_ADDRESS WITH STATIC_REPLACE(value='[EMAIL]');"
        out = compile_and_run(src, "Mail a@b.com here.").filtered_text
        assert "[EMAIL]" in out

    def test_zip_code_quirky_field_round_trips(self):
        # PhiSQL emits the singular zipCodeFilterStrategy; phileas must read it.
        src = "POLICY p; REDACT ZIP_CODE WITH REDACT;"
        policy_json = Compiler().compile(src).policy_json()
        assert "zipCodeFilterStrategy" in policy_json["identifiers"]["zipCode"]
        out = compile_and_run(src, "ZIP 90210 here.").filtered_text
        assert "90210" not in out

    def test_ein_round_trips(self):
        # EIN entered the catalog in redaction policy schema 1.2.0. Compiling it here
        # proves the entity name, the `ein` field, and `einFilterStrategies` agree
        # across the compiler and the engine.
        src = "POLICY p; REDACT EIN WITH REDACT;"
        policy_json = Compiler().compile(src).policy_json()
        assert "einFilterStrategies" in policy_json["identifiers"]["ein"]
        out = compile_and_run(src, "EIN 12-3456789 here.").filtered_text
        assert "12-3456789" not in out
        assert "{{{REDACTED-ein}}}" in out

    def test_ein_and_ssn_together(self):
        src = "POLICY p; DEIDENTIFY EIN AS REDACT, SSN AS REDACT;"
        out = compile_and_run(src, "EIN 12-3456789, SSN 123-45-6789.").filtered_text
        assert "{{{REDACTED-ein}}}" in out
        assert "{{{REDACTED-ssn}}}" in out

    def test_phone_number_region_round_trips(self):
        # PhiSQL 1.2.0 compiles OPTIONS(region=...) to a `region` key on the node.
        src = "POLICY p; REDACT PHONE_NUMBER WITH REDACT OPTIONS(region='GB');"
        policy_json = Compiler().compile(src).policy_json()
        assert policy_json["identifiers"]["phoneNumber"]["region"] == "GB"
        out = compile_and_run(src, "Ring 020 7946 0958 today.").filtered_text
        assert "020 7946 0958" not in out
        assert "{{{REDACTED-phone-number}}}" in out

    def test_phone_number_without_region_is_us(self):
        src = "POLICY p; REDACT PHONE_NUMBER WITH REDACT;"
        out = compile_and_run(src, "Ring 020 7946 0958 today.").filtered_text
        assert "020 7946 0958" in out
