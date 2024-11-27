#!/usr/bin/env python3

import socket
import sys
from time import sleep

from scapy.all import (
    IP,
    UDP,
    Ether,
    Dot1Q,
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    get_if_hwaddr,
    get_if_list,
    sendp
)
from scapy.layers.inet import _IPOption_HDR

# 利用可能なネットワークインターフェースから "eth0" を探し、その名前を返す関数
def get_if():
    ifs = get_if_list()
    iface = None
    for i in ifs:
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

# IPオプションで値を保持するクラスの定義
class IPOption_Custom(IPOption):
    name = "CustomValue"
    option = 31  # カスタムオプションの番号 (0-255から選択)
    fields_desc = [
        _IPOption_HDR,  # IPオプションの標準ヘッダー
        IntField("value", 0)  # 0~515 の値を保持
    ]

# メイン関数
def main():
    if len(sys.argv) < 5:
        print('Usage: <destination> <value (0-515)> <DSCP (0-63)> <PCP (0-7)>')
        exit(1)

    # 宛先とオプション値を取得
    addr = socket.gethostbyname(sys.argv[1])
    try:
        opt_value = int(sys.argv[2])
        dscp = int(sys.argv[3])
        pcp = int(sys.argv[4])
        if not (0 <= opt_value <= 515):
            raise ValueError("Option value out of range (0-515).")
        if not (0 <= dscp <= 63):
            raise ValueError("DSCP value out of range (0-63).")
        if not (0 <= pcp <= 7):
            raise ValueError("PCP value out of range (0-7).")
    except ValueError as e:
        print(f"Error: {e}")
        exit(1)

    # インターフェース設定
    iface = get_if()

    # TOSフィールドを計算 (DSCP << 2 | ECN)
    tos = dscp << 2  # ECN は0として設定

    # パケットの作成
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
        / Dot1Q(prio=pcp, vlan=1)  # Dot1Q タグの設定
        / IP(dst=addr, tos=tos, options=IPOption_Custom(value=opt_value))  # DSCPをTOSに設定
        / UDP(dport=4321, sport=1234)
    )

    pkt.show2()  # パケットの内容を表示

    # パケット送信
    try:
        print(f"Sending packet to {addr} with value {opt_value}, DSCP {dscp}, PCP {pcp}...")
        sendp(pkt, iface=iface)
        print("Packet sent.")
    except KeyboardInterrupt:
        print("Terminated by user.")
        exit(0)

# スクリプトが直接実行された場合にmain()を呼び出し
if __name__ == '__main__':
    main()

