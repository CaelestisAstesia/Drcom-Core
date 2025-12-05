# Mirror tests for src/drcom_core/protocols/d_series/packets.py
from drcom_core.config import DrcomConfig
from drcom_core.protocols.d_series import constants, packets


def test_build_challenge_request():
    padding = b"\x00" * 15
    pkt = packets.build_challenge_request(padding)
    assert pkt.startswith(constants.Code.CHALLENGE_REQ)
    assert len(pkt) == 20


def test_parse_challenge_response():
    salt = b"\x11\x22\x33\x44"
    data = constants.Code.CHALLENGE_RESP + b"\x00\x00\x00" + salt + b"\x00" * 20
    assert packets.parse_challenge_response(data) == salt
    assert packets.parse_challenge_response(b"\x03" + b"\x00" * 20) is None


def _create_dummy_config() -> DrcomConfig:
    return DrcomConfig(
        username="test",
        password="123",
        server_address="127.0.0.1",
        server_port=61440,
        bind_ip="0.0.0.0",
        protocol_version="D",
        mac_address=0x001122334455,
        host_ip_bytes=b"\x01" * 4,
        primary_dns_bytes=b"\x02" * 4,
        dhcp_address_bytes=b"\x03" * 4,
        secondary_dns_bytes=b"\x00" * 4,
        host_name="host",
        host_os="os",
        os_info_bytes=b"\xff" * 20,
        control_check_status=b"\x20",
        adapter_num=b"\x01",
        ipdog=b"\x01",
        auth_version=b"\x2c\x00",
        padding_after_ipdog=b"\x00" * 4,
        padding_after_dhcp=b"\x00" * 8,
        padding_auth_ext=b"\x00" * 2,
        ror_status=False,
        pppoe_flag=b"\x2a",
        keep_alive2_flag=b"\xdc",
        keep_alive_version=b"\xdc\x02",
    )


def test_build_login_packet_structure():
    config = _create_dummy_config()
    salt = b"\x00" * 4
    pkt = packets.build_login_packet(config, salt)

    assert pkt.startswith(constants.Code.LOGIN_REQ)
    assert b"\xff" * 20 in pkt
    assert len(pkt) > 300


def test_build_login_packet_randomness():
    config = _create_dummy_config()
    salt = b"\x00" * 4

    pkt1 = packets.build_login_packet(config, salt)
    pkt2 = packets.build_login_packet(config, salt)

    assert pkt1 != pkt2
    assert len(pkt1) == len(pkt2)


def test_parse_login_response():
    data_ok = (
        bytes([constants.Code.LOGIN_RESP_SUCC])
        + b"\x00" * 22
        + b"A" * 16
        + b"\x00" * 10
    )
    success, info, err = packets.parse_login_response(data_ok)
    assert success is True


def test_keep_alive1_build_parse():
    pkt = packets.build_keep_alive1_packet(b"salt", "pass", b"token" * 3)
    assert pkt.startswith(constants.Code.KEEP_ALIVE_1)


def test_keep_alive2_build():
    pkt = packets.build_keep_alive2_packet(
        1, b"\x00" * 4, 1, b"\x00" * 4, b"\xdc\x02", True
    )
    assert pkt[6:8] == b"\x0f\x27"


def test_parse_keep_alive2_tail():
    tail = b"\xaa\xbb\xcc\xdd"
    data = constants.Code.MISC + b"\x00" * 15 + tail + b"\x00" * 10
    assert packets.parse_keep_alive2_response(data) == tail


def test_logout_build():
    pkt = packets.build_logout_packet("u", "p", b"salt", 0x0, b"token", b"\x20", b"\x01")
    assert pkt.startswith(constants.Code.LOGOUT_REQ)
