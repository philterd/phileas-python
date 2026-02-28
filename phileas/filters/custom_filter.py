from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, List, Optional

from phileas.models.span import Span
from .base import BaseFilter, FilterType

if TYPE_CHECKING:
    from phileas.policy.identifiers import CustomFilterConfig
    from phileas.policy.policy import Policy


class CustomFilter(ABC):
    """Interface for user-provided custom entity filters.

    Implement this class to wire in named-entity recognition models or other
    custom logic without introducing heavy library dependencies into phileas.
    """

    @abstractmethod
    def filter(self, policy: "Policy", context: str, text: str) -> List[Span]:
        """Identify spans of sensitive information in text.

        Args:
            policy: The active :class:`~phileas.policy.policy.Policy` object.
            context: The context string.
            text: The input text to scan.

        Returns:
            A list of :class:`~phileas.models.span.Span` objects identifying
            sensitive tokens.
        """
        ...


class CustomFilterWrapper(BaseFilter):
    """Wraps a user-provided :class:`CustomFilter` implementation."""

    def __init__(self, filter_config: "CustomFilterConfig", policy: Optional["Policy"] = None):
        super().__init__(FilterType.CUSTOM, filter_config)
        self._policy = policy

    def filter(self, text: str, context: str = "default") -> List[Span]:
        implementation = getattr(self.filter_config, "implementation", None)
        if implementation is None:
            return []
        return implementation.filter(self._policy, context, text)
