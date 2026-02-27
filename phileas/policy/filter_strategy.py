from __future__ import annotations

import hashlib


class FilterStrategy:
    REDACT = "REDACT"
    RANDOM_REPLACE = "RANDOM_REPLACE"
    STATIC_REPLACE = "STATIC_REPLACE"
    CRYPTO_REPLACE = "CRYPTO_REPLACE"
    HASH_SHA256_REPLACE = "HASH_SHA256_REPLACE"
    LAST_4 = "LAST_4"
    MASK = "MASK"
    SAME = "SAME"
    TRUNCATE = "TRUNCATE"
    ABBREVIATE = "ABBREVIATE"

    DEFAULT_REDACTION_FORMAT = "{{{REDACTED-%t}}}"

    def __init__(
        self,
        strategy: str = "REDACT",
        redaction_format: str = "{{{REDACTED-%t}}}",
        static_replacement: str = "",
        mask_character: str = "*",
        mask_length: str = "SAME",
        condition: str = "",
    ):
        self.strategy = strategy
        self.redaction_format = redaction_format
        self.static_replacement = static_replacement
        self.mask_character = mask_character
        self.mask_length = mask_length
        self.condition = condition

    def get_replacement(self, filter_type: str, token: str) -> str:
        """Return the replacement value for a token based on the strategy."""
        if self.strategy == FilterStrategy.REDACT:
            return self.redaction_format.replace("%t", filter_type)
        elif self.strategy == FilterStrategy.MASK:
            return self.mask_character * len(token)
        elif self.strategy == FilterStrategy.STATIC_REPLACE:
            return self.static_replacement
        elif self.strategy == FilterStrategy.HASH_SHA256_REPLACE:
            return hashlib.sha256(token.encode()).hexdigest()
        elif self.strategy == FilterStrategy.LAST_4:
            return "*" * (len(token) - 4) + token[-4:] if len(token) > 4 else token
        elif self.strategy == FilterStrategy.SAME:
            return token
        elif self.strategy == FilterStrategy.TRUNCATE:
            return token[:4] if len(token) > 4 else token
        elif self.strategy == FilterStrategy.ABBREVIATE:
            words = token.split()
            return "".join(w[0].upper() for w in words if w)
        else:
            return self.redaction_format.replace("%t", filter_type)

    @classmethod
    def from_dict(cls, data: dict) -> "FilterStrategy":
        return cls(
            strategy=data.get("strategy", "REDACT"),
            redaction_format=data.get("redactionFormat", "{{{REDACTED-%t}}}"),
            static_replacement=data.get("staticReplacement", ""),
            mask_character=data.get("maskCharacter", "*"),
            mask_length=data.get("maskLength", "SAME"),
            condition=data.get("condition", ""),
        )

    def to_dict(self) -> dict:
        return {
            "strategy": self.strategy,
            "redactionFormat": self.redaction_format,
            "staticReplacement": self.static_replacement,
            "maskCharacter": self.mask_character,
            "maskLength": self.mask_length,
            "condition": self.condition,
        }
