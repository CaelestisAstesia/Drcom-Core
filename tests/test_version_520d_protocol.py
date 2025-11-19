# tests/test_network.py
import socket
from unittest.mock import patch

import pytest

from drcom_core.exceptions import NetworkError
from drcom_core.network import NetworkClient


@pytest.fixture
def mock_socket_cls():
    """Mock socket.socket 类"""
    with patch("socket.socket") as mock_sock:
        yield mock_sock


def test_network_init_success(valid_config, mock_socket_cls):
    """测试正常初始化"""
    client = NetworkClient(valid_config)

    mock_socket_cls.assert_called_once()
    client.sock.bind.assert_called_with((valid_config.bind_ip, valid_config.drcom_port))


def test_network_init_fail(valid_config, mock_socket_cls):
    """测试绑定端口失败"""
    mock_instance = mock_socket_cls.return_value
    mock_instance.bind.side_effect = socket.error("Address already in use")

    with pytest.raises(NetworkError, match="端口绑定失败"):
        NetworkClient(valid_config)


def test_send_fail(valid_config, mock_socket_cls):
    """测试发送失败"""
    client = NetworkClient(valid_config)
    client.sock.sendto.side_effect = socket.error("Network unreachable")

    with pytest.raises(NetworkError, match="发送失败"):
        client.send(b"test_data")


def test_receive_timeout(valid_config, mock_socket_cls):
    """测试接收超时"""
    client = NetworkClient(valid_config)
    client.sock.recvfrom.side_effect = socket.timeout()

    with pytest.raises(NetworkError, match="接收超时"):
        client.receive(timeout=1)


def test_close_socket(valid_config, mock_socket_cls):
    """测试资源释放"""
    client = NetworkClient(valid_config)

    # 关键修正：先获取 mock 对象的引用
    mock_sock_instance = client.sock

    client.close()

    # 验证是在 mock 对象上调用的 close
    mock_sock_instance.close.assert_called_once()
    assert client.sock is None
