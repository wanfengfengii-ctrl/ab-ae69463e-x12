"""X12 interchange envelope auditor.

Validates the ISA/IEA interchange, GS/GE functional-group and ST/SE
transaction-set envelopes of one raw X12 interchange. Segments are checked
in document order and the first defect is raised, so an outer summary
segment (GE/IEA) never masks an earlier inner-envelope error.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

MAX_PAYLOAD_BYTES = 2 * 1024 * 1024  # 2 MiB
MAX_GROUPS_PER_INTERCHANGE = 64
MAX_TRANSACTIONS_PER_GROUP = 500

ISA_SEGMENT_LENGTH = 106  # fixed-width ISA including the segment terminator
_ELEMENT_SEPARATOR_OFFSET = 3
_COMPONENT_SEPARATOR_OFFSET = 104
_SEGMENT_TERMINATOR_OFFSET = 105

# Fixed ISA offsets (0-based) that must carry the element separator.
_ISA_SEPARATOR_POSITIONS = (
    3, 6, 17, 20, 31, 34, 50, 53, 69, 76, 81, 83, 89, 99, 101, 103,
)


class AuditError(Exception):
    """Envelope audit failure with a stable code and a locatable segment."""

    def __init__(self, code: str, message: str, segment: int | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.segment = segment


@dataclass(frozen=True)
class AuditResult:
    interchange_control_number: str
    groups: int
    transactions: int
    sha256: str


def audit(payload: bytes) -> AuditResult:
    """Audit one raw X12 interchange.

    Returns envelope counters and the SHA-256 of the exact bytes received.
    Raises AuditError with the earliest defect in document order.
    """
    if not payload:
        raise AuditError("PAYLOAD_EMPTY", "request body is empty")
    if len(payload) > MAX_PAYLOAD_BYTES:
        raise AuditError(
            "PAYLOAD_TOO_LARGE",
            f"payload is {len(payload)} bytes; the limit is {MAX_PAYLOAD_BYTES}",
        )
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise AuditError(
            "NON_ASCII_PAYLOAD",
            f"byte offset {exc.start} is not ASCII",
        ) from None

    text = text.lstrip("\r\n")
    element_sep, _component_sep, segment_term = _read_isa_delimiters(text)
    segments = _split_segments(text, segment_term)
    return _audit_segments(segments, element_sep, payload)


def _read_isa_delimiters(text: str) -> tuple[str, str, str]:
    """Extract the three delimiters from the fixed-length ISA segment."""
    if not text.startswith("ISA"):
        raise AuditError(
            "MISSING_ISA", "payload does not begin with an ISA segment", 1
        )
    if len(text) < ISA_SEGMENT_LENGTH:
        raise AuditError(
            "ISA_TRUNCATED",
            f"ISA segment must be {ISA_SEGMENT_LENGTH} characters; "
            f"payload has {len(text)}",
            1,
        )

    element_sep = text[_ELEMENT_SEPARATOR_OFFSET]
    component_sep = text[_COMPONENT_SEPARATOR_OFFSET]
    segment_term = text[_SEGMENT_TERMINATOR_OFFSET]

    if not _is_delimiter(element_sep, allow_whitespace=False):
        raise AuditError(
            "INVALID_DELIMITERS",
            f"element separator {element_sep!r} must be a printable, "
            "non-alphanumeric, non-whitespace character",
            1,
        )
    if not _is_delimiter(component_sep, allow_whitespace=False):
        raise AuditError(
            "INVALID_DELIMITERS",
            f"component separator {component_sep!r} must be a printable, "
            "non-alphanumeric, non-whitespace character",
            1,
        )
    if not _is_delimiter(segment_term, allow_whitespace=True):
        raise AuditError(
            "INVALID_DELIMITERS",
            f"segment terminator {segment_term!r} must not be alphanumeric",
            1,
        )
    if len({element_sep, component_sep, segment_term}) != 3:
        raise AuditError(
            "INVALID_DELIMITERS",
            "element separator, component separator and segment terminator "
            "must be three distinct characters",
            1,
        )

    for pos in _ISA_SEPARATOR_POSITIONS:
        if text[pos] != element_sep:
            raise AuditError(
                "ISA_MALFORMED",
                f"ISA fixed position {pos + 1} must be the element "
                f"separator {element_sep!r}, found {text[pos]!r}",
                1,
            )
    return element_sep, component_sep, segment_term


def _is_delimiter(char: str, allow_whitespace: bool) -> bool:
    if char.isalnum():
        return False
    if char.isspace():
        return allow_whitespace
    return char.isprintable()


def _split_segments(text: str, segment_term: str) -> list[str]:
    """Split the interchange into segments, tolerating CRLF pretty-printing."""
    segments = []
    for chunk in text.split(segment_term):
        stripped = chunk.strip("\r\n")
        if stripped.strip():
            segments.append(stripped)

    isa_head = text[: ISA_SEGMENT_LENGTH - 1]
    if not segments or segments[0] != isa_head:
        raise AuditError(
            "ISA_MALFORMED",
            "ISA segment is not terminated at fixed position 106",
            1,
        )
    return segments


def _element(elements: list[str], index: int, name: str, ordinal: int) -> str:
    if len(elements) <= index or elements[index] == "":
        raise AuditError(
            "MALFORMED_SEGMENT", f"{name} is missing or empty", ordinal
        )
    return elements[index]


def _count_element(elements: list[str], index: int, name: str, ordinal: int) -> int:
    raw = _element(elements, index, name, ordinal)
    try:
        value = int(raw)
    except ValueError:
        raise AuditError(
            "MALFORMED_SEGMENT", f"{name} value {raw!r} is not an integer", ordinal
        ) from None
    if value < 0:
        raise AuditError(
            "MALFORMED_SEGMENT", f"{name} value {raw!r} must not be negative", ordinal
        )
    return value


def _audit_segments(
    segments: list[str], element_sep: str, payload: bytes
) -> AuditResult:
    isa_control = ""
    state = "EXPECT_GS"  # EXPECT_GS -> IN_GROUP -> IN_TRANSACTION -> CLOSED
    groups = 0
    transactions = 0
    gs_control = ""
    gs_ordinal = 0
    group_transactions = 0
    st_control = ""
    st_ordinal = 0
    txn_segments = 0
    last_ordinal = 0

    for ordinal, segment in enumerate(segments, start=1):
        last_ordinal = ordinal
        elements = segment.split(element_sep)
        tag = elements[0]

        if ordinal == 1:
            if len(elements) != 17:
                raise AuditError(
                    "ISA_MALFORMED",
                    f"ISA segment must carry 16 elements; found "
                    f"{len(elements) - 1}",
                    1,
                )
            isa_control = elements[13]
            continue

        if state == "CLOSED":
            raise AuditError(
                "TRAILING_DATA",
                f"{tag} segment follows the closing IEA segment",
                ordinal,
            )
        if tag == "ISA":
            raise AuditError(
                "UNEXPECTED_SEGMENT",
                "a second ISA segment appears inside the interchange",
                ordinal,
            )

        if tag == "GS":
            if state != "EXPECT_GS":
                raise AuditError(
                    "UNEXPECTED_SEGMENT",
                    "GS segment opens a group inside an unclosed envelope",
                    ordinal,
                )
            groups += 1
            if groups > MAX_GROUPS_PER_INTERCHANGE:
                raise AuditError(
                    "GROUP_LIMIT_EXCEEDED",
                    f"interchange holds more than {MAX_GROUPS_PER_INTERCHANGE} "
                    "functional groups",
                    ordinal,
                )
            gs_control = _element(elements, 6, "GS06", ordinal)
            gs_ordinal = ordinal
            group_transactions = 0
            state = "IN_GROUP"
        elif tag == "ST":
            if state != "IN_GROUP":
                raise AuditError(
                    "UNEXPECTED_SEGMENT",
                    "ST segment appears outside a functional group",
                    ordinal,
                )
            group_transactions += 1
            if group_transactions > MAX_TRANSACTIONS_PER_GROUP:
                raise AuditError(
                    "TRANSACTION_LIMIT_EXCEEDED",
                    f"functional group holds more than "
                    f"{MAX_TRANSACTIONS_PER_GROUP} transaction sets",
                    ordinal,
                )
            st_control = _element(elements, 2, "ST02", ordinal)
            st_ordinal = ordinal
            txn_segments = 1
            state = "IN_TRANSACTION"
        elif tag == "SE":
            if state != "IN_TRANSACTION":
                raise AuditError(
                    "UNEXPECTED_SEGMENT",
                    "SE segment has no matching ST segment",
                    ordinal,
                )
            txn_segments += 1
            declared = _count_element(elements, 1, "SE01", ordinal)
            if declared != txn_segments:
                raise AuditError(
                    "SEGMENT_COUNT_MISMATCH",
                    f"SE01 declares {declared} segment(s) but {txn_segments} "
                    "were counted from ST through SE",
                    ordinal,
                )
            se_control = _element(elements, 2, "SE02", ordinal)
            if se_control != st_control:
                raise AuditError(
                    "CONTROL_NUMBER_MISMATCH",
                    f"SE02 {se_control!r} does not match ST02 {st_control!r}",
                    ordinal,
                )
            transactions += 1
            state = "IN_GROUP"
        elif tag == "GE":
            if state != "IN_GROUP":
                raise AuditError(
                    "UNEXPECTED_SEGMENT",
                    "GE segment has no matching GS segment",
                    ordinal,
                )
            if group_transactions == 0:
                raise AuditError(
                    "EMPTY_GROUP",
                    "functional group contains no transaction sets",
                    ordinal,
                )
            declared = _count_element(elements, 1, "GE01", ordinal)
            if declared != group_transactions:
                raise AuditError(
                    "TRANSACTION_COUNT_MISMATCH",
                    f"GE01 declares {declared} transaction set(s) but "
                    f"{group_transactions} were counted in the group",
                    ordinal,
                )
            ge_control = _element(elements, 2, "GE02", ordinal)
            if ge_control != gs_control:
                raise AuditError(
                    "CONTROL_NUMBER_MISMATCH",
                    f"GE02 {ge_control!r} does not match GS06 {gs_control!r}",
                    ordinal,
                )
            state = "EXPECT_GS"
        elif tag == "IEA":
            if state != "EXPECT_GS":
                raise AuditError(
                    "UNEXPECTED_SEGMENT",
                    "IEA segment closes the interchange inside an unclosed "
                    "envelope",
                    ordinal,
                )
            if groups == 0:
                raise AuditError(
                    "NO_GROUPS",
                    "interchange contains no functional groups",
                    ordinal,
                )
            declared = _count_element(elements, 1, "IEA01", ordinal)
            if declared != groups:
                raise AuditError(
                    "GROUP_COUNT_MISMATCH",
                    f"IEA01 declares {declared} functional group(s) but "
                    f"{groups} were counted in the interchange",
                    ordinal,
                )
            iea_control = _element(elements, 2, "IEA02", ordinal)
            if iea_control != isa_control:
                raise AuditError(
                    "CONTROL_NUMBER_MISMATCH",
                    f"IEA02 {iea_control!r} does not match ISA13 "
                    f"{isa_control!r}",
                    ordinal,
                )
            state = "CLOSED"
        else:
            if state != "IN_TRANSACTION":
                raise AuditError(
                    "UNEXPECTED_SEGMENT",
                    f"{tag} segment appears outside a transaction set",
                    ordinal,
                )
            txn_segments += 1

    if state == "IN_TRANSACTION":
        raise AuditError(
            "MISSING_SE",
            "transaction set is not closed by an SE segment",
            st_ordinal,
        )
    if state == "IN_GROUP":
        raise AuditError(
            "MISSING_GE",
            "functional group is not closed by a GE segment",
            gs_ordinal,
        )
    if state != "CLOSED":
        if groups == 0:
            raise AuditError(
                "NO_GROUPS", "interchange contains no functional groups", 1
            )
        raise AuditError(
            "MISSING_IEA",
            "interchange is not closed by an IEA segment",
            last_ordinal,
        )

    return AuditResult(
        interchange_control_number=isa_control,
        groups=groups,
        transactions=transactions,
        sha256=hashlib.sha256(payload).hexdigest(),
    )
