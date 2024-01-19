from enum import Enum
from struct import pack, unpack

A_VERSION = 0x01000001
TOKEN_SIZE = 20
MAX_PAYLOAD = 1024 * 1024
CONNECTION_PROPERTIES = 'host::features=shell_v2,cmd,stat_v2,ls_v2,fixed_push_mkdir,apex,abb,fixed_push_symlink_timestamp,abb_exec,remount_shell,track_app,sendrecv_v2,sendrecv_v2_brotli,sendrecv_v2_lz4,sendrecv_v2_zstd,sendrecv_v2_dry_run_send,openscreen_mdns'

class ENUM_STATE(Enum):
    """Adb状态
    """
    ONLINE = 'online'
    OFFLINE = 'offline'
    DISCONNECT = 'disconnect'
    UNAUTHORIZED = 'unauthorized'

class ENUM_COMMAND(Enum):
    """Adb command
    """
    A_SYNC = 0x434e5953
    A_CNXN = 0x4e584e43
    A_OPEN = 0x4e45504f
    A_OKAY = 0x59414b4f
    A_CLSE = 0x45534c43
    A_WRTE = 0x45545257
    A_AUTH = 0x48545541
    A_STLS = 0x534C5453

class ENUM_ADB_AUTH(Enum):
    """Adb认证参数
    """
    TOKEN = 1
    SIGNATURE = 2
    RSAPUBLICKEY =  3

class Amessage():
    """Adb协议头信息

    Args:
        command (int): 命令
        arg0 (int): 参数1
        arg1 (int): 参数1
        data_length (int): 数据长度
        data_check (int): 数据校验
        magic (int): command ^ 0xffffffff
    """
    def __init__(self, command: int, arg0: int, arg1: int, data_length: int, data_check: int, magic: int):
        try:
            self.command = ENUM_COMMAND(command)
        except:
            self.command = None
        self.arg0 = arg0
        self.arg1 = arg1
        self.data_length = data_length
        self.data_check = data_check
        self.magic = magic

class Apacket():
    """Adb数据包

    Args:
        data (bytes, optional): 数据, 默认值=b''.
        amessage (Amessage, optional): 协议头, 默认值=None.
    """
    def __init__(self, data: bytes = b'', amessage: Amessage = None):
        self.data = data
        self.amessage = amessage

    def check(self) -> bool:
        """检查数据合法性

        Returns:
            bool
        """
        return self.amessage and isinstance(self.amessage.command, ENUM_COMMAND)
        

def encode_data(command: ENUM_COMMAND, arg0: int, arg1: int, payload: bytes = b'') -> bytes:
    """
    Args:
        command (ENUM_COMMAND): Adb命令
        arg0 (int): 参数1
        arg1 (int): 参数2
        payload (bytes): 发送的数据
    Returns:
        bytes
    """
    data_length = len(payload)
    data_check = 0
    for num in payload:
        data_check += num
    magic = command.value ^ 0xffffffff
    data = (command.value, arg0, arg1, data_length, data_check, magic)

    return pack('IIIIII', *data) + payload

def decode_data(data: bytes) -> Apacket:
    """
    Args:
        data (bytes)

    Returns:
        Apacket
    """
    try:
        payload = data[24:]
        amessage = Amessage(*unpack('IIIIII', data[0: 24]))
        return Apacket(payload, amessage)
    except:
        return Apacket(b'', Amessage(*(0, 0, 0, 0, 0, 0)))