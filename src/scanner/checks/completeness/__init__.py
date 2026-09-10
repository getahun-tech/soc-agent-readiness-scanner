from scanner.checks.completeness.c1_event_identification import C1EventIdentification
from scanner.checks.completeness.c2_temporal import C2TemporalQuality
from scanner.checks.completeness.c3_location import C3EventLocation
from scanner.checks.completeness.c4_affected_entity import C4AffectedEntity
from scanner.checks.completeness.c5_outcome import C5Outcome
from scanner.checks.completeness.c6_causality import C6Causality
from scanner.checks.completeness.c7_correlatability import C7Correlatability
from scanner.checks.completeness.c8_actor import C8Actor

COMPLETENESS_CHECKS = [
    C1EventIdentification(),
    C2TemporalQuality(),
    C3EventLocation(),
    C4AffectedEntity(),
    C5Outcome(),
    C6Causality(),
    C7Correlatability(),
    C8Actor(),
]

__all__ = [
    "COMPLETENESS_CHECKS",
    "C1EventIdentification",
    "C2TemporalQuality",
    "C3EventLocation",
    "C4AffectedEntity",
    "C5Outcome",
    "C6Causality",
    "C7Correlatability",
    "C8Actor",
]
