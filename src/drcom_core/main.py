import os
import socket
import sys
from pathlib import Path

import netifaces
from dotenv import load_dotenv


class DrcomCore:
    def __init__(self):
        # Initialize Dr.com-Core configurations.
        # Load all necessary settings from environment variables.
        # Pepare network sockets for communication.

        # Load all configurations.
        print("Dr.Com-Core initializing.")
        self._load_config()

        # Initialize network socket.
        print("Initializing network sockets.")
        self.core_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.core_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.core_socket.bind((self.bind_ip, 61440))
        self.core_socket.settimeout(3)

        # Initialize other necessary attributes.
        self.salt = b""
        self.auth_info = b""

        print("Network sockets initialized successfully.")

    def _detect_campus_ip(self):
        # Automatically detect campus network IP address.
        print("Detecting campus network IP address automatically.")
        try:
            # netifaces.interfaces() will return a list of all network interfaces'
            for interface in netifaces.interfaces():
                # netifaces.ifaddresses(interface) will return a dictionary of addresses for the given interface
                addresses = netifaces.ifaddresses(interface)
                # Only consider IPv4 addresses
                if socket.AF_INET in addresses:
                    # addresses[socket.AF_INET] is a list of dictionaries, each containing info about an IPv4 address
                    for addr_info in addresses[socket.AF_INET]:
                        ip = addr_info.get("addr")
                        # Accroding
                        if ip and ip.startswith("49."):
                            print(f"Campus ip : {ip}")
                            return ip
        except Exception as e:
            print(f"Automatic detection error: {e}")

        print("Auotomatic detection failed, please set HOST_IP in .env file.")
        return os.getenv("HOST_IP")

    def _load_config(self):
        # Load configuration settings from an environment.
        # DO NOT use this function directly outside __init__.
        print("Loading configurations.")
        env_path = Path(__file__).resolve().parent.parent.parent / ".env"

        if env_path.exists():
            load_dotenv(dotenv_path=env_path, override=True)
        else:
            print(".env file not found.")
            sys.exit("Exiting.")

        # Source address and Diretion address , and other address.
        self.server_address = os.getenv("SERVER_IP")
        self.dhcp_address = os.getenv("DHCP_SERVER")
        self.primary_dns = os.getenv("PRIMARY_DNS")
        self.host_ip = self._detect_campus_ip()
        self.bind_ip = self.host_ip
        # self.bind_ip = os.getenv("BIND_IP", "0.0.0.0") Use this line if you need to bind to all interfaces.
        # User credentials.
        self.username = os.getenv("USERNAME")
        self.password = os.getenv("PASSWORD")
        # Host information.
        self.host_name = os.getenv("HOST_NAME")
        self.host_os = os.getenv("HOST_OS")
        self.mac_address = (
            os.getenv("MAC").replace("-", "").replace(":", "")
        )  # Get 16-based MAC address.
        self.mac_address = (
            int(self.mac_address, 16) if self.mac_address else 0
        )  # Convert to 10-based integer.
        self.adapter_num = bytes.fromhex(os.getenv("ADAPTERNUM", "01"))
        self.ipdog = bytes.fromhex(os.getenv("IPDOG", "01"))
        # Protocol configurations.
        self.auth_version = bytes.fromhex(os.getenv("AUTH_VERSION", "0a00"))
        self.control_check_status = bytes.fromhex(
            os.getenv("CONTROL_CHECK_STATUS", "20")
        )
        self.ror_status = os.getenv("ROR_STATUS", "False").lower() in ("true", "1", "t")

        print("All Configurations loaded successfully.")


# main function test version
def main():
    try:
        core = DrcomCore()
        print("Dr.Com-Core initialized successfully.")
        print(f"Authentic Server: {core.server_address}, Username: {core.username}")
        print(f"Authentic Versions : {core.auth_version}")

    except Exception as e:
        print(f"Something goes wrong : {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
