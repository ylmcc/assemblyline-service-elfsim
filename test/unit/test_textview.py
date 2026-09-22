from elfsim_service.textview import line_summary, printable_ratio, readable, strip_ansi, text_runs


def test_printable_ascii_is_shown_as_is():
    assert readable(b"GET / HTTP/1.1") == "GET / HTTP/1.1"


def test_control_bytes_are_a_placeholder_not_hex_dumped():
    assert readable(b"\x00\x00\x00\x01\x04px86\x03x86") == "·····px86·x86"


def test_common_whitespace_and_backslash_are_readable_escapes():
    assert readable(b"a\r\nb\tc\\d") == "a\\r\\nb\\tc\\\\d"


def test_long_data_is_truncated_with_the_number_of_bytes_left_out():
    assert readable(b"A" * 10, limit=4) == "AAAA ... (+6 more bytes)"


def test_text_runs_finds_the_names_hidden_in_a_binary_protocol():
    assert text_runs(b"\x00\x00\x00\x01\x04px86\x03x86") == ["px86", "x86"]


def test_text_runs_ignores_short_noise():
    assert text_runs(b"\x00ab\x01\x02") == []


def test_ansi_colour_codes_are_stripped_for_display():
    assert strip_ansi(b"\x1b[0m[\x1b[1;31mSnoopy.\x1b[0m] \x1b[1;31m>\x1b[0m") == b"[Snoopy.] >"


def test_binary_data_with_stray_escape_bytes_is_left_alone():
    assert strip_ansi(b"\x1b\x00\x01\xff") == b"\x1b\x00\x01\xff"


def test_text_runs_are_deduplicated_in_first_seen_order():
    assert text_runs(b"root\x00admin\x00root\x00admin\x00support") == ["root", "admin", "support"]


def test_printable_ratio_separates_text_from_binary():
    assert printable_ratio(b"root\r\nadmin\r\n") == 1.0 and printable_ratio(bytes(range(256))) < 0.5


def test_line_summary_counts_repeated_lines_most_frequent_first():
    total, distinct, top = line_summary(b"root\r\nadmin\r\nroot\r\nroot\r\nguest\r\n")
    assert (total, distinct) == (5, 3) and top[0] == ("root", 3)
