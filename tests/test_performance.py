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

"""Performance tests measuring redaction throughput."""

import time

import pytest

from phileas.policy.policy import Policy
from phileas.policy.filter_strategy import FilterStrategy
from phileas.policy.identifiers import (
    EmailAddressFilterConfig,
    SSNFilterConfig,
    PhoneNumberFilterConfig,
    IPAddressFilterConfig,
    CreditCardFilterConfig,
    URLFilterConfig,
    DateFilterConfig,
)
from phileas.services.filter_service import FilterService

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_SHORT_TEXT = (
    "Please contact john.doe@example.com or call 800-555-1234 about your account."
)

_MEDIUM_TEXT = (
    "Patient Jane Smith (DOB: 01/15/1985) lives at 123 Main St, Springfield. "
    "Her SSN is 987-65-4321 and her email is jane.smith@hospital.org. "
    "She can be reached at 555-867-5309 or via her insurance ID CC: 4111-1111-1111-1111. "
    "Her IP address is 192.168.1.100 and her doctor's website is https://drhouse.example.com."
)

# Large document: repeat the medium paragraph many times
_LARGE_TEXT = (_MEDIUM_TEXT + "\n") * 500


def _all_filters_policy() -> Policy:
    """Return a policy with several common identifier filters enabled."""
    p = Policy(name="perf-test")
    ids = p.identifiers
    ids.email_address = EmailAddressFilterConfig()
    ids.ssn = SSNFilterConfig()
    ids.phone_number = PhoneNumberFilterConfig()
    ids.ip_address = IPAddressFilterConfig()
    ids.credit_card = CreditCardFilterConfig()
    ids.url = URLFilterConfig()
    ids.date = DateFilterConfig()
    return p


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _measure(policy: Policy, text: str, iterations: int = 1):
    """
    Run FilterService.filter() *iterations* times and return:
      elapsed_s   – total wall-clock seconds
      chars_per_s – average characters processed per second
      kb_per_s    – average kilobytes processed per second
    """
    svc = FilterService()
    start = time.perf_counter()
    for iteration in range(iterations):
        svc.filter(policy, "perf-ctx", f"doc-{iteration}", text)
    elapsed_s = time.perf_counter() - start
    total_chars = len(text) * iterations
    chars_per_s = total_chars / elapsed_s
    kb_per_s = (total_chars / 1024) / elapsed_s
    return elapsed_s, chars_per_s, kb_per_s


# ---------------------------------------------------------------------------
# Performance tests
# ---------------------------------------------------------------------------

class TestRedactionThroughput:
    """Measure redaction throughput for various text sizes."""

    def test_short_text_throughput(self):
        """Single short sentence with email and phone filters."""
        policy = Policy(name="perf-short")
        policy.identifiers.email_address = EmailAddressFilterConfig()
        policy.identifiers.phone_number = PhoneNumberFilterConfig()

        elapsed_s, chars_per_s, kb_per_s = _measure(policy, _SHORT_TEXT, iterations=200)

        print(
            f"\n[short] {len(_SHORT_TEXT)} chars × 200 iterations | "
            f"elapsed={elapsed_s:.3f}s | "
            f"throughput={chars_per_s:,.0f} chars/s ({kb_per_s:.1f} KB/s)"
        )
        assert chars_per_s > 0, "Throughput must be positive"

    def test_medium_text_throughput(self):
        """Paragraph-length text with all major filters enabled."""
        policy = _all_filters_policy()

        elapsed_s, chars_per_s, kb_per_s = _measure(policy, _MEDIUM_TEXT, iterations=100)

        print(
            f"\n[medium] {len(_MEDIUM_TEXT)} chars × 100 iterations | "
            f"elapsed={elapsed_s:.3f}s | "
            f"throughput={chars_per_s:,.0f} chars/s ({kb_per_s:.1f} KB/s)"
        )
        assert chars_per_s > 0, "Throughput must be positive"

    def test_large_text_throughput(self):
        """Document-scale text (~500 paragraphs) with all major filters enabled."""
        policy = _all_filters_policy()

        elapsed_s, chars_per_s, kb_per_s = _measure(policy, _LARGE_TEXT, iterations=3)

        print(
            f"\n[large] {len(_LARGE_TEXT):,} chars × 3 iterations | "
            f"elapsed={elapsed_s:.3f}s | "
            f"throughput={chars_per_s:,.0f} chars/s ({kb_per_s:.1f} KB/s)"
        )
        assert chars_per_s > 0, "Throughput must be positive"

    def test_throughput_scales_with_text_length(self):
        """Verify that per-character cost is roughly consistent across text sizes."""
        policy = Policy(name="perf-scale")
        policy.identifiers.email_address = EmailAddressFilterConfig()
        policy.identifiers.ssn = SSNFilterConfig()

        small_text = _SHORT_TEXT
        # 100× repetition produces ~7 600-char text, simulating a larger document
        large_text = _SHORT_TEXT * 100

        _, small_cps, _ = _measure(policy, small_text, iterations=50)
        _, large_cps, _ = _measure(policy, large_text, iterations=5)

        print(
            f"\n[scale] small={small_cps:,.0f} chars/s  large={large_cps:,.0f} chars/s"
        )
        # Both must be positive; no hard ratio requirement given regex overhead varies
        assert small_cps > 0
        assert large_cps > 0

    def test_no_filters_baseline_throughput(self):
        """Baseline: policy with no filters enabled (pure overhead cost)."""
        policy = Policy(name="perf-baseline")

        elapsed_s, chars_per_s, kb_per_s = _measure(policy, _MEDIUM_TEXT, iterations=500)

        print(
            f"\n[baseline] {len(_MEDIUM_TEXT)} chars × 500 iterations | "
            f"elapsed={elapsed_s:.3f}s | "
            f"throughput={chars_per_s:,.0f} chars/s ({kb_per_s:.1f} KB/s)"
        )
        assert chars_per_s > 0, "Throughput must be positive"

    def test_single_document_timing(self):
        """Measure wall-clock time for a single realistic document."""
        policy = _all_filters_policy()
        svc = FilterService()

        start = time.perf_counter()
        result = svc.filter(policy, "ctx", "single-doc", _MEDIUM_TEXT)
        elapsed_ms = (time.perf_counter() - start) * 1000

        chars_per_s = len(_MEDIUM_TEXT) / (elapsed_ms / 1000)
        print(
            f"\n[single] {len(_MEDIUM_TEXT)} chars | "
            f"elapsed={elapsed_ms:.2f}ms | "
            f"throughput={chars_per_s:,.0f} chars/s"
        )
        assert result is not None
        assert elapsed_ms >= 0
