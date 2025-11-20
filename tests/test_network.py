# tests/test_network.py
import socket
from unittest.mock import patch

import pytest

from drcom_core.network import NetworkClient, NetworkError


def test_network_init(valid_config):
    with patch("socket.socket") as mock_sock:
        client = NetworkClient(valid_config)
        mock_sock.return_value.bind.assert_called_with(
            (valid_config.bind_ip, valid_config.drcom_port)
        )


def test_network_send_error(valid_config):
    with patch("socket.socket") as mock_sock:
        client = NetworkClient(valid_config)
        client.sock.sendto.side_effect = socket.error("Mock Error")

        with pytest.raises(NetworkError):
            client.send(b"data")


def test_network_receive_timeout(valid_config):
    with patch("socket.socket") as mock_sock:
        client = NetworkClient(valid_config)
        client.sock.recvfrom.side_effect = socket.timeout

        with pytest.raises(NetworkError, match="超时"):
            client.receive(1.0)
