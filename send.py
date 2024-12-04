#!/usr/bin/env python3

import socket
import sys
from scapy.all import (
    IP,
    UDP,
    Ether,
    Dot1Q,
    FieldLenField,
    ByteField,
    ShortField,
    Packet,
    get_if_hwaddr,
    get_if_list,
    sendp
)

# ネットワークインターフェースの取得
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

# カスタムIPオプション (ipv4_option_t + link_qos_t) の定義
class IPOption_Custom(Packet):
    name = "CustomOption"
    fields_desc = [
        ByteField("copy_flag_and_class_and_option", 0),  # 1bit + 2bits + 5bits
        ByteField("option_length", 4),                 # オプション長 (固定値4)
        ShortField("link_qos", 0)                      # 16bitのリンクQoS値
    ]

# メイン関数
def main():
    if len(sys.argv) < 5:
        print('Usage: <destination> <link_qos (0-65535)> <DSCP (0-63)> <PCP (0-7)>')
        exit(1)

    # 宛先とオプション値を取得
    addr = socket.gethostbyname(sys.argv[1])
    try:
        link_qos = int(sys.argv[2])
        dscp = int(sys.argv[3])
        pcp = int(sys.argv[4])
        if not (0 <= link_qos <= 65535):
            raise ValueError("link_qos value out of range (0-65535).")
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

    # カスタムオプションのヘッダ値を計算
    copy_flag = 1      # 1bit
    opt_class = 0      # 2bits (control options)
    option = 31        # 5bits (カスタムオプション番号)
    option_header = (copy_flag << 7) | (opt_class << 5) | option

    # パケットの作成
    pkt = (
        Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff")
        / Dot1Q(prio=pcp, vlan=1)  # Dot1Q タグの設定
        / IP(dst=addr, tos=tos, options=IPOption_Custom(copy_flag_and_class_and_option=option_header, option_length=4, link_qos=link_qos))
        / UDP(dport=4321, sport=1234)
    )

    pkt.show2()  # パケットの内容を表示

    # パケット送信
    try:
        print(f"Sending packet to {addr} with link_qos {link_qos}, DSCP {dscp}, PCP {pcp}...")
        sendp(pkt, iface=iface)
        print("Packet sent.")
    except KeyboardInterrupt:
        print("Terminated by user.")
        exit(0)

# スクリプトが直接実行された場合にmain()を呼び出し
if __name__ == '__main__':
    main()

