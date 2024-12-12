/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// IPv4の定義
const bit<16> TYPE_IPV4 = 0x800;
// IPオプションの定義
const bit<5> IPV4_OPTION_LINK_QOS = 31;

/* IP protocols */
// プロトコルの定義
const bit<8> IP_PROTOCOLS_ICMP       =   1;
const bit<8> IP_PROTOCOLS_IGMP       =   2;
const bit<8> IP_PROTOCOLS_IPV4       =   4;
const bit<8> IP_PROTOCOLS_TCP        =   6;
const bit<8> IP_PROTOCOLS_UDP        =  17;
const bit<8> IP_PROTOCOLS_IPV6       =  41;
const bit<8> IP_PROTOCOLS_GRE        =  47;
const bit<8> IP_PROTOCOLS_IPSEC_ESP  =  50;
const bit<8> IP_PROTOCOLS_IPSEC_AH   =  51;
const bit<8> IP_PROTOCOLS_ICMPV6     =  58;
const bit<8> IP_PROTOCOLS_EIGRP      =  88;
const bit<8> IP_PROTOCOLS_OSPF       =  89;
const bit<8> IP_PROTOCOLS_PIM        = 103;
const bit<8> IP_PROTOCOLS_VRRP       = 112;

const bit<8> TARGET_DSCP = 52;
const bit<3> TARGET_PCP = 7;
const bit<16> TARGET_LINK_QOS = 500;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> qosOption_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header vlan_t {
    bit<3> pcp;
    bit<1> dei;
    bit<12> id;
    bit<16> etherType;
}

// tos部分をdiffservとecnに分けて定義
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header link_qos_t{
    bit<16> link_qos;
}

struct metadata{
}

// ヘッダーが持つ型を定義
struct headers {
    ethernet_t   ethernet;
    vlan_t	 vlan;
    ipv4_t       ipv4;
    ipv4_option_t ipv4_option;
    link_qos_t link_qos;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// パーサーとはパケットのヘッダーとメタデータをマッピングする機能のこと

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
	    0x8100: parse_vlan;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_vlan {
	packet.extract(hdr.vlan);
	transition select(hdr.vlan.etherType) {
	    TYPE_IPV4: parse_ipv4;
	    default: accept;
	}
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
	verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
	    5		: accept;
	    default	: parse_ipv4_option;
	}
    }

    state parse_ipv4_option {
	packet.extract(hdr.ipv4_option);
	transition select(hdr.ipv4_option.option){
	    IPV4_OPTION_LINK_QOS: parse_link_qos;
	    default: accept;
	}
    }

    state parse_link_qos {
	packet.extract(hdr.link_qos);
	transition accept;
    }

}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }


    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    apply {	
	if ( hdr.ipv4.isValid() ) {
            if (hdr.link_qos.link_qos == TARGET_LINK_QOS) {
        	hdr.ipv4.diffserv = (TARGET_DSCP << 2);
        	hdr.vlan.pcp = TARGET_PCP;
            }
	    ipv4_lpm.apply();
	}
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}


/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
	      hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.vlan);
        packet.emit(hdr.ipv4);
	packet.emit(hdr.ipv4_option);
	packet.emit(hdr.link_qos);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
