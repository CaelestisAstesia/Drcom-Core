# tests/test_protocols_misc.py
from drcom_core.protocols import challenge, constants, keep_alive, logout

# --- Challenge Tests ---


def test_challenge_build_and_parse():
    """测试 Challenge 构建和解析"""
    # 1. 构建
    req = challenge.build_challenge_request()
    assert req.startswith(constants.CHALLENGE_REQ_CODE)
    assert len(req) == 20

    # 2. 解析成功
    # 构造一个模拟的响应: 02 01 [Random 2B] [Salt 4B] ...
    mock_salt = b"\x11\x22\x33\x44"
    mock_resp = (
        constants.CHALLENGE_RESP_CODE + b"\x01\x00\x00" + mock_salt + b"\x00" * 10
    )
    parsed_salt = challenge.parse_challenge_response(mock_resp)
    assert parsed_salt == mock_salt


def test_challenge_parse_fail():
    """测试 Challenge 解析失败情况"""
    # 响应太短
    assert challenge.parse_challenge_response(b"\x02\x01") is None
    # 响应Code不对
    assert challenge.parse_challenge_response(b"\xff" * 20) is None


# --- Keep Alive Tests ---


def test_keep_alive1_flow():
    """测试 KA1 (FF包) 构建和解析"""
    salt = b"\x11\x22\x33\x44"
    auth_info = b"A" * 16  # 模拟 Auth Info

    # 1. 构建
    pkt = keep_alive.build_keep_alive1_packet(salt, "password", auth_info)
    assert pkt.startswith(constants.KEEP_ALIVE_CLIENT_CODE)  # \xff
    assert len(pkt) == 42  # 1(code)+16(md5)+3(pad)+16(auth)+2(time)+4(pad)

    # 2. 解析成功
    assert keep_alive.parse_keep_alive1_response(constants.KEEP_ALIVE_RESP_CODE) is True
    # 3. 解析失败
    assert keep_alive.parse_keep_alive1_response(b"\x00") is False


def test_keep_alive2_build():
    """测试 KA2 (07包) 构建"""
    tail = b"\x00\x00\x00\x00"
    host_ip = b"\x7f\x00\x00\x01"
    ver = constants.KEEP_ALIVE_VERSION

    # Type 1
    pkt1 = keep_alive.build_keep_alive2_packet(0, tail, 1, host_ip, ver)
    assert pkt1[5] == 1  # Type
    assert pkt1.endswith(constants.KA2_TYPE1_SPECIFIC_PART)

    # Type 3
    pkt3 = keep_alive.build_keep_alive2_packet(1, tail, 3, host_ip, ver)
    assert pkt3[5] == 3  # Type
    # 验证包含 IP
    assert host_ip in pkt3


def test_keep_alive2_parse():
    """测试 KA2 解析 Tail"""
    # 模拟响应: 头(16B) + Tail(4B) + ...
    mock_tail = b"\xaa\xbb\xcc\xdd"
    mock_resp = constants.KEEP_ALIVE_RESP_CODE + b"\x00" * 15 + mock_tail + b"\x00" * 10

    extracted = keep_alive.parse_keep_alive2_response(mock_resp)
    assert extracted == mock_tail

    # 失败测试
    assert keep_alive.parse_keep_alive2_response(b"\x07") is None  # 太短


# --- Logout Tests ---


def test_logout_flow():
    """测试登出包构建"""
    salt = b"\x11\x22\x33\x44"
    auth_info = b"A" * 16

    pkt = logout.build_logout_packet(
        "user", "pass", salt, 0x0, auth_info, b"\x20", b"\x01"
    )
    assert pkt.startswith(constants.LOGOUT_REQ_CODE)  # 06

    # 测试解析
    # 1. 无响应视为成功
    assert logout.parse_logout_response(None, "1.1.1.1", None)[0] is True
    # 2. 收到 0x04 视为成功
    assert logout.parse_logout_response(b"\x04", "1.1.1.1", "1.1.1.1")[0] is True
