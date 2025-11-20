# tests/test_protocols_misc.py
from drcom_core.protocols import challenge, constants, keep_alive, logout


# --- Challenge ---
def test_challenge_build():
    pkt = challenge.build_challenge_request()
    assert pkt.startswith(constants.CHALLENGE_REQ_CODE)
    assert len(pkt) == 20


def test_challenge_parse_success():
    salt = b"\x01\x02\x03\x04"
    resp = constants.CHALLENGE_RESP_CODE + b"\x01\x00\x00" + salt + b"\x00" * 10
    assert challenge.parse_challenge_response(resp) == salt


# --- Keep Alive ---
def test_ka1_build_and_parse():
    pkt = keep_alive.build_keep_alive1_packet(b"salt", "pass", b"A" * 16)
    assert pkt.startswith(constants.KEEP_ALIVE_CLIENT_CODE)
    assert keep_alive.parse_keep_alive1_response(constants.KEEP_ALIVE_RESP_CODE) is True


def test_ka2_build_and_parse():
    tail = b"\x00" * 4
    host_ip = b"\x01\x02\x03\x04"
    pkt1 = keep_alive.build_keep_alive2_packet(0, tail, 1, host_ip, b"\xdc\x02")
    assert len(pkt1) > 0

    new_tail = b"\xaa\xbb\xcc\xdd"
    # Code(0x07) + ... + Tail(16:20) + ...
    resp = constants.KEEP_ALIVE_RESP_CODE + b"\x00" * 15 + new_tail + b"\x00" * 5
    assert keep_alive.parse_keep_alive2_response(resp) == new_tail


# --- Logout ---
def test_logout_build_and_parse():
    pkt = logout.build_logout_packet(
        "u", "p", b"salt", 0x0, b"A" * 16, b"\x20", b"\x01"
    )
    assert pkt.startswith(constants.LOGOUT_REQ_CODE)
    # 无响应视为成功
    assert logout.parse_logout_response(None, "1.1.1.1", None)[0] is True
