from adb_type import *

import socket
from M2Crypto import RSA
from getpass import getuser
from socket import gethostname


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
        self.__client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        """socket 实例
        """
        self.__client.settimeout(timeout)

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
            self.__client.getpeername()
            return True
        except:
            self.__state = ENUM_STATE.DISCONNECT
            return False

    def __send(self, data: bytes) -> int:
        """发送数据

        Args:
            data (bytes)

        Returns:
            int: 成功发送的字节数
        """
        if self.__check_connect():
            return self.__client.send(data)
        return 0

    def __recv(self) -> Apacket:
        """接收数据

        Returns:
            bytes
        """
        apacket = Apacket()
        try:
            if self.__check_connect():
                recv_data = self.__client.recv(24)
                apacket.amessage = Amessage(*unpack("IIIIII", recv_data))
                length = apacket.amessage.data_length
                while length > 0:
                    data_temp = self.__client.recv(1024 if length > 1024 else length)
                    apacket.data += data_temp
                    length = length - len(data_temp)
        except:
            pass

        return apacket

    def __send_signature(self, data: bytes):
        """数字签名
        Args:
            data (bytes)
        """

        self.__is_signature = True
        signature = self.__private_cert.sign(data)
        self.__send(
            encode_data(
                ENUM_COMMAND.A_AUTH, ENUM_ADB_AUTH.SIGNATURE.value, 0, signature
            )
        )

    def __send_publickey(self) -> None:
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
        self.__send(
            encode_data(ENUM_COMMAND.A_AUTH, ENUM_ADB_AUTH.RSAPUBLICKEY.value, 0, data)
        )

    def __authentication(self) -> None:
        """自动认证"""
        if self.__state is ENUM_STATE.DISCONNECT:
            try:
                self.__client.connect((self.__connect_host, self.__connect_port))
            except:
                return None
            self.__state = ENUM_STATE.UNAUTHORIZED
        self.__send(
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
            apacket = self.__recv()
            if apacket.amessage == None:
                break
            elif apacket.amessage.command == ENUM_COMMAND.A_AUTH:
                if not self.__is_signature or self.__state == ENUM_STATE.ONLINE:
                    self.__send_signature(apacket.data)
                else:
                    self.__send_publickey()
            elif apacket.amessage.command == ENUM_COMMAND.A_CNXN:
                self.__state = ENUM_STATE.ONLINE
                break
            elif apacket.amessage.command in [ENUM_COMMAND.A_WRTE, ENUM_COMMAND.A_OKAY]:
                data += apacket.data
                self.__send(
                    encode_data(
                        ENUM_COMMAND.A_OKAY,
                        self.__client.fileno(),
                        apacket.amessage.arg0,
                    )
                )
            elif apacket.amessage.command == ENUM_COMMAND.A_CLSE:
                self.__send(
                    encode_data(
                        ENUM_COMMAND.A_CLSE,
                        self.__client.fileno(),
                        apacket.amessage.arg0,
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
        self.__send(encode_data(ENUM_COMMAND.A_OPEN, self.__client.fileno(), 0, data))
        result = self.__handle_packet()
        return result


if __name__ == "__main__":
    client = Adb("127.0.0.1", 16384)
    # client = Adb('192.168.1.16', 16243)
    # client = Adb('192.168.1.22', 5555)
    while True:
        text = input(
            "[{}@{}]".format(client.username.decode(), client.hostname.decode())
        )
        if text in ["q", "Q"]:
            break
        if text == "state":
            print(client.state())
        if text[:6] == "shell ":
            print(client.shell(text[6:]))
