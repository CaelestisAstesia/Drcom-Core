---
layout: default
title: 配置参考
nav_order: 4
---

# 配置文件参考

`drcom-core` 使用 **TOML** 格式进行配置管理。默认配置文件名为 `config.toml`。

## 1. 核心身份凭据 (Identity)

这些是认证通过所必须的最基本信息。

| 键名 (Key) | 类型 | 必填 | 描述 | 部分选项示例 |
| :--- | :--- | :--- | :--- | :--- |
| `username` | String | 是 | 您的账号或学号等。 | `"student001"` |
| `password` | String | 是 | 您的密码。 | `"123456"` |
| `server_ip` | String | 是 | 认证服务器的 IP 地址。<br>通常是校园网内的一个特定 IP。 | `"10.100.61.3"` |
| `mac` | String | 是 | 本机网卡的物理地址 (MAC)。<br>支持使用 `-` 或 `:` 分隔，也支持纯 Hex 字符串。 | `"00-11-22-33-44-55"` |

## 2. 网络环境 (Network)

这些参数描述了您当前的内网环境，它们会被打包发送给服务器以进行校验。

| 键名 (Key) | 类型 | 必填 | 描述 | 示例 |
| :--- | :--- | :--- | :--- | :--- |
| `host_ip` | String | 是 | 本机用于上网的 IP 地址。<br>通常是 DHCP 分配的内网 IP。 | `"49.123.123.123"` |
| `primary_dns` | String | 是 | 首选 DNS 服务器 IP。 | `"10.10.10.10"` |
| `dhcp_server` | String | 是 | DHCP 服务器或网关的 IP 地址。 | `"49.123.123.123"` |
| `bind_ip` | String | 否 | Drcom-Core 绑定的本地网卡 IP。<br>默认为 `0.0.0.0` (监听所有网卡)。 | `"0.0.0.0"` |
| `drcom_port` | Int | 否 | Dr.COM 协议通讯端口。<br>默认为 `61440`。 | `61440` |

## 3. 协议控制 (Protocol Control)

| 键名 (Key) | 类型 | 必填 | 描述 | 示例 |
| :--- | :--- | :--- | :--- | :--- |
| `protocol_version` | String | 是 | 协议大版本号。目前仅支持 `"D"` (代表 5.2.0 D 版)。 | `"D"` |
| `ror_status` | Bool | 否 | 是否启用 ROR 防重放机制。<br>目前尚未实装，建议保持 `false`。 | `false` |

## 4. 主机指纹 (Host Fingerprint)

这些参数用于伪装客户端类型，这是 Dr.COM 协议反检测的核心。

| 键名 (Key) | 类型 | 必填 | 描述 |
| :--- | :--- | :--- | :--- |
| `host_name` | String | 是 | 主机名，会明文发送给服务器。建议填一个普通的名字。 |
| `host_os` | String | 是 | 操作系统名称。如 `"Windows 10"`。 |
| `os_info_hex` | String | 是 | **关键参数**。系统内核版本信息的二进制 Hex 字符串。<br>通常为 20 字节 (40 个 Hex 字符)。<br>不同学校对该校验的严格程度不同，如遇登录失败，请尝试抓包获取真实客户端的值。<br>示例 (Win10): `"940000000600000000000000280a000002000000"` |

## 5. 协议魔数 (Magic Numbers)

这些是 Dr.COM 客户端内部的固定常量，随客户端版本（如 5.2.0, 5.2.1, P版, X版）的不同而不同。
**请直接填写 Hex 字符串，无需 `0x` 前缀。**

| 键名 (Key) | 长度 | 描述 | 常见值 |
| :--- | :--- | :--- | :--- |
| `adapter_num` | 1 Byte | 网卡序号/标识 | `"01"` |
| `ipdog` | 1 Byte | IPDOG 标志位 | `"01"` |
| `auth_version` | 2 Bytes | 认证版本号 | `"2c00"` (对应 5.2.0 D) |
| `control_check_status` | 1 Byte | 控制位状态 | `"20"` |
| `keep_alive_version` | 2 Bytes | 心跳协议版本号 | `"dc02"` |

---

## 附录：完整配置模板 (Configuration Template)

您可以直接复制以下内容到 `config.toml` 文件中，并根据实际情况修改。

```toml
# config.toml
# Drcom-Core 配置文件
# 吉林大学的同学只需要修改 username, password, mac, host_ip, dhcp_server, host_name

[drcom]
# --- 核心身份凭据 ---
username = "your_username"
password = "your_password"
server_ip = "10.100.61.3"      # 认证服务器 IP
mac = "00-11-22-33-44-55"      # 你的 MAC 地址 (支持 - 或 :)

# --- 网络环境 ---
host_ip = "192.168.1.100"      # 本机 IP (ipconfig/ifconfig 获取)
primary_dns = "10.10.10.10"    # 首选 DNS
dhcp_server = "192.168.1.1"    # 网关/DHCP 服务器
bind_ip = "0.0.0.0"            # 本地绑定 IP (通常无需修改)
drcom_port = 61440             # 协议端口 (通常无需修改)

# --- 协议控制 ---
protocol_version = "D"         # 目前仅支持 "D" 版
ror_status = false             # ROR 防重放 (暂未实现，保持 false)

# --- 主机指纹 ---
host_name = "Drcom-Core"       # 主机名 (任意字符串)
host_os = "Windows 10"         # 操作系统标识 (任意字符串)

# 系统环境指纹 (OS Info) - 必需
# 这是一段表示系统版本的二进制数据 (Hex 格式)。
# 示例值对应 Windows 10 (Major 6, Build 10240)
os_info_hex = "940000000600000000000000280a000002000000"

# --- 协议魔数 (Hex 格式, 无需 0x 前缀) ---
# 以下值为 Dr.COM 5.2.0(D) 版的标准默认值
adapter_num = "01"
ipdog = "01"
auth_version = "2c00"
control_check_status = "20"
keep_alive_version = "dc02"
