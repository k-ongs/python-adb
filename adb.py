from .adb_base import *

import os
import time
import stat
import socket
from M2Crypto import RSA
from getpass import getuser
from socket import gethostname

from .adb_sync import AdbSync


class Adb:
    def __init__(self, host: str, port: int = 5555, timeout: int = 5):
        """
        Args:
            host (str): Adb连接地址
            post (int, optional): Adb连接端口, 默认值=5555.
            timeout (int, optional): 超时时间, 默认值=5.
        """

        self.__state = ENUM_STATE.DISCONNECT
        """Adb连接状态
        """
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        """socket 实例
        """
        self.client.settimeout(timeout)

        self.username = getuser().encode()
        """当前用户名
        """
        self.hostname = gethostname().encode()
        """当前主机名
        """
        self.__connect_host = host
        """连接地址
        """
        self.__connect_port = port
        """连接端口
        """
        self.__public_cert = b""
        """公钥 - android pre-computed RSAPublicKey
        """
        self.__private_cert = RSA.load_key_string(b"")
        """私钥
        """
        self.__is_signature = False
        """是否签名, 如果一直返回A_AUTH, 就尝试发送证书授权
        """

        self.__authentication()

    def __check_connect(self) -> bool:
        """检查是否连接

        Returns:
            bool
        """
        try:
            self.client.getpeername()
            return True
        except:
            self.__state = ENUM_STATE.DISCONNECT
            return False

    def send(self, data: bytes) -> int:
        """发送数据

        Args:
            data (bytes)

        Returns:
            int: 成功发送的字节数
        """
        if self.__check_connect():
            return self.client.send(data)
        return 0

    def recv(self) -> Apacket:
        """接收数据

        Returns:
            bytes
        """
        apacket = Apacket()
        try:
            if self.__check_connect():
                recv_data = self.client.recv(24)
                apacket.amessage = Amessage(*unpack("IIIIII", recv_data))
                length = apacket.amessage.data_length
                while length > 0:
                    data_temp = self.client.recv(1024 if length > 1024 else length)
                    apacket.data += data_temp
                    length = length - len(data_temp)
        except:
            pass

        return apacket

    def send_signature(self, data: bytes):
        """数字签名
        Args:
            data (bytes)
        """

        self.__is_signature = True
        signature = self.__private_cert.sign(data)
        self.send(
            encode_data(
                ENUM_COMMAND.A_AUTH, ENUM_ADB_AUTH.SIGNATURE.value, 0, signature
            )
        )

    def send_publickey(self) -> None:
        """发送公钥"""
        self.__is_signature = False
        data = (
            self.__public_cert
            + b" "
            + self.username
            + b"@"
            + self.hostname
            + bytes([0x00])
        )
        self.send(
            encode_data(ENUM_COMMAND.A_AUTH, ENUM_ADB_AUTH.RSAPUBLICKEY.value, 0, data)
        )

    def __authentication(self) -> None:
        """自动认证"""
        if self.__state is ENUM_STATE.DISCONNECT:
            try:
                self.client.connect((self.__connect_host, self.__connect_port))
            except:
                return None
            self.__state = ENUM_STATE.UNAUTHORIZED
        self.send(
            encode_data(
                ENUM_COMMAND.A_CNXN,
                A_VERSION,
                MAX_PAYLOAD,
                CONNECTION_PROPERTIES.encode("utf-8"),
            )
        )
        self.__handle_packet()

    def __handle_packet(self) -> bytes:
        """请求处理

        Returns:
            bytes
        """
        data = b""
        while True:
            apacket = self.recv()
            if apacket.amessage == None:
                break
            elif apacket.amessage.command == ENUM_COMMAND.A_AUTH:
                if not self.__is_signature or self.__state == ENUM_STATE.ONLINE:
                    self.send_signature(apacket.data)
                else:
                    self.send_publickey()
            elif apacket.amessage.command == ENUM_COMMAND.A_CNXN:
                self.__state = ENUM_STATE.ONLINE
                break
            elif apacket.amessage.command in [ENUM_COMMAND.A_WRTE, ENUM_COMMAND.A_OKAY]:
                data += apacket.data
                self.send(
                    encode_data(
                        ENUM_COMMAND.A_OKAY, self.client.fileno(), apacket.amessage.arg0
                    )
                )
            elif apacket.amessage.command == ENUM_COMMAND.A_CLSE:
                self.send(
                    encode_data(
                        ENUM_COMMAND.A_CLSE, self.client.fileno(), apacket.amessage.arg0
                    )
                )
                break

        return data

    def state(self) -> str:
        """获取连接状态

        Returns:
            str
        """
        if self.__state is ENUM_STATE.DISCONNECT:
            self.__authentication()
        return self.__state.value

    def shell(self, text: str) -> bytes:
        """adb shell 命令
        Args:
            text (str): 命令

        Returns:
            bytes
        """
        data = b"shell:" + text.encode() + b"\x00"
        self.send(encode_data(ENUM_COMMAND.A_OPEN, self.client.fileno(), 0, data))
        result = self.__handle_packet()
        return result

    def debug_log(self, name, apacket: Apacket):
        print("======>>> {:^10} >>>======".format(name))
        data = apacket.data.hex()
        i = 0
        for text1 in [data[i * 2] + data[i * 2 + 1] for i in range(len(data) // 2)]:
            i = i + 1
            end = ""
            text2 = " "
            if i == 4:
                text2 = " | "
            if i == 8:
                text2 = "   "
                end = "\n"
                i = 0
            print(text1 + text2, end=end)
        if apacket.amessage:
            print(apacket.amessage.command)
        print("======<<< {:^10} <<<======".format(name))
        print()

    def push(self, text: str) -> bool:
        source_path, target_path = text.encode().split(b" ")
        client_fileno = self.client.fileno()

        if not os.path.exists(source_path):
            print('路径"{}"不存在'.format(source_path.decode()))
            return False

        # 获取源路径的类型和权限
        source_st_mode = os.stat(source_path).st_mode

        data = b"sync:" + b"\x00"
        self.send(encode_data(ENUM_COMMAND.A_OPEN, client_fileno, 0, data))
        apacket = self.recv()
        if (
            not isinstance(apacket.amessage, Amessage)
            or apacket.amessage.command != ENUM_COMMAND.A_OKAY
        ):
            print("连接失败")
            return False

        myself_fileno = apacket.amessage.arg0

        # 判断路径是否存在
        payload = b"STA2" + pack("I", len(target_path)) + target_path
        self.send(
            encode_data(ENUM_COMMAND.A_WRTE, client_fileno, myself_fileno, payload)
        )
        # 这里会返回一个A_OKAY
        self.recv()
        # 返回路径的stat信息
        apacket = self.recv()
        # 获取目标路径的类型和权限
        target_st_mode = int.from_bytes(apacket.data[24:26], byteorder="little")
        self.send(encode_data(ENUM_COMMAND.A_OKAY, client_fileno, myself_fileno, b""))

        adb_sync = AdbSync(self, client_fileno, myself_fileno)

        # 文件夹无法上传到一个文件
        if stat.S_ISREG(target_st_mode) and stat.S_ISDIR(source_st_mode):
            print('"{}"不是一个文件夹')
            adb_sync.quit(myself_fileno)
            return False

        if stat.S_ISREG(source_st_mode) and stat.S_ISDIR(target_st_mode):
            target_path = os.path.join(target_path, os.path.basename(source_path))

        adb_sync.find_file(source_path, target_path)
        adb_sync.quit(myself_fileno)

        return {"succ": adb_sync.succ_num, "fail": adb_sync.fail_num}
