#!/usr/bin/env python3
import sys
from scapy.all import (
    ByteField,
    ShortField,
    Packet,
    sniff
)

# 利用可能なネットワークインターフェースのうち、"eth0" を検索して返す関数
def get_if():
    from scapy.all import get_if_list
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

# カスタムIPオプションの定義 (ipv4_option_t + link_qos_t)
class IPOption_Custom(Packet):
    name = "CustomOption"
    fields_desc = [
        ByteField("copy_flag_and_class_and_option", 0),  # 1bit + 2bits + 5bits
        ByteField("option_length", 4),                 # オプション長 (固定値4)
        ShortField("link_qos", 0)                      # 16bitのリンクQoS値
    ]

# パケットを受信したときに呼び出される関数
def handle_pkt(pkt):
    print("Received a packet:")
    pkt.show2()  # パケットの内容を表示

    # Dot1Q タグの確認
    if pkt.haslayer("Dot1Q"):
        vlan_info = pkt["Dot1Q"]
        print(f"VLAN ID: {vlan_info.vlan}, Priority (PCP): {vlan_info.prio}")

    # IPヘッダーの確認とDSCP値の表示
    if pkt.haslayer("IP"):
        ip_layer = pkt["IP"]
        tos = ip_layer.tos
        dscp = tos >> 2  # DSCPはTOSの上位6ビット
        print(f"DSCP: {dscp}")

        # IPオプションのカスタム値を表示
        if ip_layer.options:
            for opt in ip_layer.options:
                if isinstance(opt, IPOption_Custom):
                    # カスタムオプションの値を分解して表示
                    copy_flag = (opt.copy_flag_and_class_and_option >> 7) & 0x1
                    opt_class = (opt.copy_flag_and_class_and_option >> 5) & 0x3
                    option = opt.copy_flag_and_class_and_option & 0x1F
                    print(f"Custom IP Option:")
                    print(f"  Copy Flag: {copy_flag}")
                    print(f"  Option Class: {opt_class}")
                    print(f"  Option: {option}")
                    print(f"  Link QoS: {opt.link_qos}")
                    break

    sys.stdout.flush()  # 出力をフラッシュ

# メイン関数
def main():
    iface = get_if()  # 使用するインターフェースを取得
    print(f"Sniffing on {iface}...")
    sys.stdout.flush()

    # パケットキャプチャ
    sniff(
        filter="udp and port 4321",  # UDPパケットでポート4321をフィルタリング
        iface=iface,                 # 使用するインターフェース
        prn=lambda x: handle_pkt(x)  # パケット受信時に handle_pkt を呼び出す
    )

# スクリプトが直接実行された場合にmain()を呼び出し
if __name__ == '__main__':
    main()

