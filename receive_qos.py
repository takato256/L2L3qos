#!/usr/bin/env python3
import sys

from scapy.all import (
    IntField,
    IPOption,
    Packet,
    sniff
)
from scapy.layers.inet import _IPOption_HDR

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

# IPオプションにカスタム値を格納するクラス
class IPOption_Custom(IPOption):
    name = "CustomValue"
    option = 31  # オプション番号
    fields_desc = [
        _IPOption_HDR,  # IPオプションの標準ヘッダー
        IntField("value", 0)  # 0~515 の値を保持するフィールド
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
                    print(f"Custom IP Option Value: {opt.value}")
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

