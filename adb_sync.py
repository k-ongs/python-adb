import os
import time
import zstd
from .adb_base import *


class AdbSync:
    def __init__(self, adb, client_fileno, myself_fileno) -> None:
        self.adb = adb
        self.succ_num = 0
        self.fail_num = 0
        self.myself_fileno = myself_fileno
        self.client_fileno = client_fileno

    # 小于64KB的文件使用这个方法
    def __file_send(self, source_path, source_stat, target_path):
        target_info = target_path + b"," + str(source_stat.st_mode).encode()
        with open(source_path, "rb") as file:
            file_data = file.read()
        payload = (
            b"SEND"
            + pack("I", len(target_info))
            + target_info
            + b"DATA"
            + pack("I", len(file_data))
            + file_data
            + b"DONE"
            + pack("I", int(time.time()))
        )

        self.adb.send(
            encode_data(
                ENUM_COMMAND.A_WRTE, self.client_fileno, self.myself_fileno, payload
            )
        )
        apacket: Apacket = self.adb.recv()
        if apacket.data[:4] == b"FAIL":
            print(apacket.data.decode())
            self.fail_num = self.fail_num + 1
        else:
            self.succ_num = self.succ_num + 1

    # 大于或等于64KB的文件使用这个方法
    def __file_snd2(self, source_path, source_stat, target_path):
        payload = (
            b"SND2"
            + pack("I", len(target_path))
            + target_path
            + b"SND2"
            + pack("I", source_stat.st_mode)
            + b"\x04\x00\x00\x00"
        )
        self.adb.send(
            encode_data(
                ENUM_COMMAND.A_WRTE, self.client_fileno, self.myself_fileno, payload
            )
        )
        apacket: Apacket = self.adb.recv()

        if apacket.amessage is None or apacket.amessage.command != ENUM_COMMAND.A_OKAY:
            return False
        with open(source_path, "rb") as file:
            data = file.read()
        compressed = zstd.compress(data, 4)

        payload_start = b""
        if len(compressed) < 65536:
            payload_start = b"DATA"

        while len(compressed) >= 65536:
            data = compressed[:65536]
            payload = b"DATA" + pack("I", len(data)) + data
            self.adb.send(
                encode_data(
                    ENUM_COMMAND.A_WRTE, self.client_fileno, self.myself_fileno, payload
                )
            )
            apacket: Apacket = self.adb.recv()
            if (
                apacket.amessage is None
                or apacket.amessage.command != ENUM_COMMAND.A_OKAY
            ):
                time.sleep(0.5)
            else:
                compressed = compressed[65536:]

        if len(payload_start):
            payload_start += pack("I", len(compressed))
        payload = payload_start + compressed + b"DONE" + pack("I", int(time.time()))
        self.adb.send(
            encode_data(
                ENUM_COMMAND.A_WRTE, self.client_fileno, self.myself_fileno, payload
            )
        )
        apacket: Apacket = self.adb.recv()
        if apacket.data[:4] == b"FAIL":
            print(apacket.data.decode())
            self.fail_num = self.fail_num + 1
        else:
            self.succ_num = self.succ_num + 1

    def quit(self, arg0):
        self.adb.send(
            encode_data(
                ENUM_COMMAND.A_WRTE,
                self.adb.client.fileno(),
                arg0,
                b"QUIT\x00\x00\x00\x00",
            )
        )
        self.adb.recv()

        apacket = self.adb.recv()
        data = encode_data(
            ENUM_COMMAND.A_CLSE, self.adb.client.fileno(), apacket.amessage.arg0, b""
        )
        self.adb.send(data)

    def find_file(self, source_path, target_path):
        if os.path.isdir(source_path):
            for filename in os.listdir(source_path):
                self.find_file(
                    os.path.join(source_path, filename),
                    os.path.join(target_path, filename),
                )
        else:
            source_stat = os.stat(source_path)
            if source_stat.st_size < 65536:
                self.__file_send(source_path, source_stat, target_path)
            else:
                self.__file_snd2(source_path, source_stat, target_path)
