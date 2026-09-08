"""Adapter contract.

SPEC.md 9.1 requires the tool be *structurally* incapable of writing to a
source: this interface declares exactly one method, and it returns data --
it never accepts data to persist. Do not add a write/delete/update method
to this class or any subclass. If a concrete adapter's underlying client
library exposes write operations, the adapter must not call them and
should fail loudly (raise) if it detects it was handed write-capable
credentials -- see the splunk adapter added in Phase 6.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator

from scanner.config import ScannerConfig, SourceConfig
from scanner.models import RawRecord, SampleMetadata


class Adapter(ABC):
    """Fetches a bounded, read-only sample of records from one source."""

    @abstractmethod
    def fetch_sample(
        self, source: SourceConfig, config: ScannerConfig
    ) -> tuple[Iterator[RawRecord], SampleMetadata]:
        """Return an iterator of at most `config.effective_sample_size(source)`
        records, plus metadata describing how the sample was drawn.
        """
        raise NotImplementedError
