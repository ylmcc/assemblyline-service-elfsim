from elfsim_service.textview import readable, text_runs


def test_printable_ascii_is_shown_as_is():
    assert readable(b"GET / HTTP/1.1") == "GET / HTTP/1.1"


def test_control_bytes_are_escaped_not_hex_dumped():
    assert readable(b"\x00\x00\x00\x01\x04px86\x03x86") == "\\x00\\x00\\x00\\x01\\x04px86\\x03x86"


def test_common_whitespace_and_backslash_are_readable_escapes():
    assert readable(b"a\r\nb\tc\\d") == "a\\r\\nb\\tc\\\\d"


def test_long_data_is_truncated_with_the_number_of_bytes_left_out():
    assert readable(b"A" * 10, limit=4) == "AAAA ... (+6 more bytes)"


def test_text_runs_finds_the_names_hidden_in_a_binary_protocol():
    assert text_runs(b"\x00\x00\x00\x01\x04px86\x03x86") == ["px86", "x86"]


def test_text_runs_ignores_short_noise():
    assert text_runs(b"\x00ab\x01\x02") == []
