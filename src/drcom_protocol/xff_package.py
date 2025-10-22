import hashlib
import binascii
import time
import struct
password = ""
salt_hex = ''
# 上述salt在Info为Start Response的UDP负载中的第5-8字节
salt = binascii.unhexlify(salt_hex)
data_for_md5 = b'\x03\x01' + salt + password.encode()
# 下面计算数据包所需要的md5的值
calculated_md5_bytes = hashlib.md5(data_for_md5).digest()
# 下面是计算数据包所用到的tail值，来自Info为Success的第23-38字节
tail_hex = ''
tail = binascii.unhexlify(tail_hex)
# 以当前时间获取时间戳
foo = struct.pack('!H', int(time.time()) % 0xFFFF)
# 构建最终的包：
packet = b'\xff' + calculated_md5_bytes + b'\x00\x00\x00' + tail + foo
packet_hex = binascii.hexlify(packet).decode()
