"""Unit tests for the X12 envelope auditor."""

from __future__ import annotations

import hashlib

import pytest

from app.x12 import (
    MAX_GROUPS_PER_INTERCHANGE,
    MAX_PAYLOAD_BYTES,
    MAX_TRANSACTIONS_PER_GROUP,
    AuditError,
    audit,
)


def isa_segment(
    control: str = "000000001",
    elem: str = "*",
    comp: str = ">",
    term: str = "~",
) -> str:
    """Build a fixed-width 106-character ISA segment."""
    fields = [
        "ISA",
        "00",
        " " * 10,
        "00",
        " " * 10,
        "ZZ",
        "SENDER".ljust(15),
        "ZZ",
        "RECEIVER".ljust(15),
        "260101",
        "1200",
        "U",
        "00401",
        control.ljust(9),
        "0",
        "T",
        comp,
    ]
    segment = elem.join(fields) + term
    assert len(segment) == 106
    return segment


def build_message(
    isa_control: str = "000000001",
    groups: list[list[tuple[str, list[str]]]] | None = None,
    term: str = "~",
    pretty: bool = False,
) -> bytes:
    """Build a structurally valid interchange.

    groups: list of groups; each group is a list of (ST02, [data segments]).
    """
    if groups is None:
        groups = [[("0001", ["BIG*20260101*PO0001"])]]
    eol = "\n" if pretty else ""
    parts = [isa_segment(isa_control, term=term), eol]
    for index, txns in enumerate(groups, start=1):
        gs_control = str(index)
        parts.append(
            f"GS*PO*SENDER*RECEIVER*20260101*1200*{gs_control}*X*004010{term}{eol}"
        )
        for st_control, data in txns:
            lines = [f"ST*850*{st_control}", *data]
            lines.append(f"SE*{len(lines) + 1}*{st_control}")
            parts.append("".join(line + term + eol for line in lines))
        parts.append(f"GE*{len(txns)}*{gs_control}{term}{eol}")
    parts.append(f"IEA*{len(groups)}*{isa_control}{term}")
    return "".join(parts).encode("ascii")


def expect_error(payload: bytes, code: str, segment: int | None) -> None:
    with pytest.raises(AuditError) as excinfo:
        audit(payload)
    assert excinfo.value.code == code
    assert excinfo.value.segment == segment


# ---------------------------------------------------------------- valid cases


def test_valid_single_group_single_transaction():
    payload = build_message()
    result = audit(payload)
    assert result.interchange_control_number == "000000001"
    assert result.groups == 1
    assert result.transactions == 1
    assert result.sha256 == hashlib.sha256(payload).hexdigest()


def test_valid_multiple_groups_and_transactions():
    payload = build_message(
        isa_control="000000042",
        groups=[
            [("0001", ["BIG*1"]), ("0002", ["BIG*2", "REF*A", "REF*B"])],
            [("0003", ["BIG*3"])],
            [("0004", ["BIG*4"]), ("0005", ["BIG*5"])],
        ],
    )
    result = audit(payload)
    assert result.interchange_control_number == "000000042"
    assert result.groups == 3
    assert result.transactions == 5


def test_pretty_printed_crlf_between_segments():
    result = audit(build_message(pretty=True))
    assert result.groups == 1
    assert result.transactions == 1


def test_newline_segment_terminator():
    result = audit(build_message(term="\n"))
    assert result.transactions == 1


def test_alternative_delimiters():
    payload = build_message()
    payload = payload.replace(b"*", b"|").replace(b">", b":").replace(b"~", b"!")
    result = audit(payload)
    assert result.transactions == 1


def test_trailing_newline_after_iea_is_tolerated():
    result = audit(build_message() + b"\r\n")
    assert result.groups == 1


def test_maximum_group_count_is_accepted():
    groups = [[("0001", ["BIG*1"])] for _ in range(MAX_GROUPS_PER_INTERCHANGE)]
    result = audit(build_message(groups=groups))
    assert result.groups == 64
    assert result.transactions == 64


def test_maximum_transaction_count_is_accepted():
    txns = [(f"{i:04d}", ["BIG*1"]) for i in range(1, MAX_TRANSACTIONS_PER_GROUP + 1)]
    result = audit(build_message(groups=[txns]))
    assert result.transactions == 500


def test_payload_at_size_limit_is_processed():
    # Pad with data segments inside the transaction up to just below 2 MiB.
    filler = "PID*F*" + "X" * 100
    count = (MAX_PAYLOAD_BYTES - 2048) // (len(filler) + 1)
    payload = build_message(groups=[[("0001", [filler] * count)]])
    assert len(payload) <= MAX_PAYLOAD_BYTES
    assert audit(payload).transactions == 1


# ------------------------------------------------------------- payload cases


def test_empty_payload():
    expect_error(b"", "PAYLOAD_EMPTY", None)


def test_payload_over_size_limit():
    expect_error(b"x" * (MAX_PAYLOAD_BYTES + 1), "PAYLOAD_TOO_LARGE", None)


def test_non_ascii_payload():
    payload = build_message()
    payload = payload[:100] + b"\xe9" + payload[101:]
    expect_error(payload, "NON_ASCII_PAYLOAD", None)


# ----------------------------------------------------------------- ISA cases


def test_missing_isa():
    expect_error(b"GS*PO*A*B*20260101*1200*1*X*004010~", "MISSING_ISA", 1)


def test_isa_truncated():
    expect_error(build_message()[:50], "ISA_TRUNCATED", 1)


def test_isa_fixed_position_violation():
    payload = bytearray(build_message())
    payload[17] = ord("X")  # separator after ISA02 must stay the element sep
    expect_error(bytes(payload), "ISA_MALFORMED", 1)


def test_isa_terminator_inside_isa():
    payload = bytearray(build_message())
    payload[10] = ord("~")  # terminator shows up inside ISA02
    expect_error(bytes(payload), "ISA_MALFORMED", 1)


def test_isa_element_count_violation():
    # An element separator inside ISA data shifts the fixed element count.
    payload = bytearray(build_message())
    payload[10] = ord("*")
    expect_error(bytes(payload), "ISA_MALFORMED", 1)


def test_component_separator_must_differ_from_element_separator():
    payload = isa_segment(comp="*").encode("ascii") + b"GS*PO~"
    expect_error(payload, "INVALID_DELIMITERS", 1)


def test_terminator_must_differ_from_element_separator():
    payload = isa_segment(term="*").encode("ascii")
    expect_error(payload, "INVALID_DELIMITERS", 1)


def test_alphanumeric_element_separator_rejected():
    payload = isa_segment(elem="0").encode("ascii")
    expect_error(payload, "INVALID_DELIMITERS", 1)


# ----------------------------------------------------------- structure cases


def test_isa_only_has_no_groups():
    expect_error(isa_segment().encode("ascii"), "NO_GROUPS", 1)


def test_iea_directly_after_isa_has_no_groups():
    payload = isa_segment().encode("ascii") + b"IEA*0*000000001~"
    expect_error(payload, "NO_GROUPS", 2)


def test_empty_group_rejected():
    payload = (
        isa_segment().encode("ascii")
        + b"GS*PO*S*R*20260101*1200*1*X*004010~"
        + b"GE*0*1~"
        + b"IEA*1*000000001~"
    )
    expect_error(payload, "EMPTY_GROUP", 3)


def test_st_outside_group():
    payload = isa_segment().encode("ascii") + b"ST*850*0001~"
    expect_error(payload, "UNEXPECTED_SEGMENT", 2)


def test_data_segment_outside_transaction():
    payload = isa_segment().encode("ascii") + b"BIG*20260101*PO1~"
    expect_error(payload, "UNEXPECTED_SEGMENT", 2)


def test_nested_isa_rejected():
    payload = build_message()
    insert_at = payload.index(b"GS*")
    payload = payload[:insert_at] + isa_segment().encode("ascii") + payload[insert_at:]
    expect_error(payload, "UNEXPECTED_SEGMENT", 2)


def test_trailing_segment_after_iea():
    payload = build_message() + b"GS*PO*S*R*20260101*1200*2*X*004010~"
    expect_error(payload, "TRAILING_DATA", 8)


def test_second_interchange_after_iea_is_trailing_data():
    payload = build_message() + build_message()
    expect_error(payload, "TRAILING_DATA", 8)


def test_group_limit_exceeded():
    groups = [[("0001", ["BIG*1"])] for _ in range(MAX_GROUPS_PER_INTERCHANGE + 1)]
    # 65th GS follows ISA + 64 groups x 5 segments each.
    expect_error(build_message(groups=groups), "GROUP_LIMIT_EXCEEDED", 1 + 64 * 5 + 1)


def test_transaction_limit_exceeded():
    txns = [(f"{i:04d}", ["BIG*1"]) for i in range(1, MAX_TRANSACTIONS_PER_GROUP + 2)]
    # 501st ST follows ISA + GS + 500 transactions x 3 segments each.
    expect_error(
        build_message(groups=[txns]), "TRANSACTION_LIMIT_EXCEEDED", 2 + 500 * 3 + 1
    )


# ----------------------------------------------------------- truncation cases


def test_missing_iea():
    payload = build_message()
    payload = payload[: payload.index(b"IEA*")]
    expect_error(payload, "MISSING_IEA", 6)


def test_missing_ge():
    payload = build_message()
    payload = payload[: payload.index(b"GE*")]
    expect_error(payload, "MISSING_GE", 2)


def test_missing_se():
    payload = build_message()
    payload = payload[: payload.index(b"SE*")]
    expect_error(payload, "MISSING_SE", 3)


# -------------------------------------------------------------- count cases


def test_se_segment_count_mismatch():
    payload = build_message().replace(b"SE*3*0001~", b"SE*9*0001~")
    expect_error(payload, "SEGMENT_COUNT_MISMATCH", 5)


def test_se_segment_count_not_numeric():
    payload = build_message().replace(b"SE*3*0001~", b"SE*ABC*0001~")
    expect_error(payload, "MALFORMED_SEGMENT", 5)


def test_ge_transaction_count_mismatch():
    payload = build_message().replace(b"GE*1*1~", b"GE*2*1~")
    expect_error(payload, "TRANSACTION_COUNT_MISMATCH", 6)


def test_iea_group_count_mismatch():
    payload = build_message().replace(b"IEA*1*", b"IEA*2*")
    expect_error(payload, "GROUP_COUNT_MISMATCH", 7)


# ------------------------------------------------- control number pair cases


def test_st_se_control_number_mismatch():
    payload = build_message().replace(b"SE*3*0001~", b"SE*3*9999~")
    expect_error(payload, "CONTROL_NUMBER_MISMATCH", 5)


def test_gs_ge_control_number_mismatch():
    payload = build_message().replace(b"GE*1*1~", b"GE*1*77~")
    expect_error(payload, "CONTROL_NUMBER_MISMATCH", 6)


def test_isa_iea_control_number_mismatch():
    payload = build_message().replace(b"IEA*1*000000001~", b"IEA*1*000000099~")
    expect_error(payload, "CONTROL_NUMBER_MISMATCH", 7)


def test_st_missing_control_number():
    payload = build_message().replace(b"ST*850*0001~", b"ST*850~")
    expect_error(payload, "MALFORMED_SEGMENT", 3)


# ------------------------------------------------------------- nesting order


def test_inner_error_beats_outer_summary_error():
    # Corrupt both the SE segment count and the IEA group count: the
    # earlier inner-envelope defect must be the one reported.
    payload = build_message()
    payload = payload.replace(b"SE*3*0001~", b"SE*9*0001~")
    payload = payload.replace(b"IEA*1*", b"IEA*7*")
    expect_error(payload, "SEGMENT_COUNT_MISMATCH", 5)


def test_group_error_beats_interchange_summary_error():
    payload = build_message()
    payload = payload.replace(b"GE*1*1~", b"GE*5*1~")
    payload = payload.replace(b"IEA*1*", b"IEA*7*")
    expect_error(payload, "TRANSACTION_COUNT_MISMATCH", 6)


def test_first_defect_in_document_order_wins():
    # Two bad transactions: the first SE defect must be reported.
    payload = build_message(groups=[[("0001", ["BIG*1"]), ("0002", ["BIG*2"])]])
    payload = payload.replace(b"SE*3*0002~", b"SE*1*0002~")
    payload = payload.replace(b"SE*3*0001~", b"SE*8*0001~")
    expect_error(payload, "SEGMENT_COUNT_MISMATCH", 5)
