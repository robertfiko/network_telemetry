/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
***************************** H E A D E R S  *****************************
*************************************************************************/
#define INT_MAX_METADATA_COUNT 12
#define SRH_MAX_SEGMENT_LIST_LENGTH 12
// Define a register to store the ingress timestamp
//register<bit<48>>(1) ingress_timestamp;
 
// Define a register to store the egress timestamp
//register<bit<48>>(1) egress_timestamp;

/*************************** E T H E R N E T ****************************/
header ethernet_header {
    bit<48> destination_mac;
    bit<48> source_mac;
    bit<16> ethertype;
}

/********************************* I N T ********************************/
header int_header_beginning {
    bit<4> ver; //version, we will keep this static
    bit<2> flags; //allow packet duplication? No.
    bit<1> M; //packet exceeds MTU? This will always be 0.
    bit<1> reserved;
    bit<5> hop_ml; //number of metadata rows already inserted in this header
    bit<8> remaining_hop_cnt; //number of switches allowed to insert their metadata
    bit<11> instruction_bitmap; //which data needs to be placed by switches, 1 bit = 1 aspect
}

header matadata {
    bit<8> switch_id;
    bit<9> in_port_id;
    bit<9> e_port_id;
    bit<48> processed_time;
    bit<6> padding; //needed to be divisiable by 8
}

/*************************** I P v 6 ********************************/
struct ipv6_addr {
    bit<128> Addr0;
}
header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ipv6_addr src;
    ipv6_addr dst;
}

/*************************** S R H ********************************/
header srh_header_beginning{
    bit<8> next_header;
    bit<8> hdr_ext_len;
    bit<8> routing_type; //a random constant number
    bit<8> segments_left; //
    bit<8> last_entry; //index of the last label
    bit<8> flags; //reserved byte
    bit<16> tag; //classification of the packet
}
header segment_list_item{
    ipv6_addr addr;
}

/*************************** P 4 ********************************/
struct metadata {
    bit<48> ingress_timestamp;
    bit<1> has_int_header;
    bit<1> have_processed;
    bit<5> matadata_to_parse;
    bit<8> segment_list_items_to_parse;
    ipv6_addr to_send_to_ipv6;
}

struct headers { //és azt be kell rakni a headers (gyűjtemény) struktúrába
    ethernet_header ethernet;
    
    //only used when no more switches want to insert their data
    ipv6_t ipv6_to_final_destination;

    int_header_beginning int_beg;
    matadata[INT_MAX_METADATA_COUNT] int_end;
    
    ipv6_t ipv6;

    srh_header_beginning srh_beg;
    segment_list_item[SRH_MAX_SEGMENT_LIST_LENGTH] srh_end;
}


/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        meta.has_int_header = 0;
        transition parse_ethernet;
    }

    state parse_ethernet{
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ethertype){
            16w0x7FFF: parse_int_beg;
            16w0x86DD: parse_ipv6;
            default: reject;
        }
    }
    state parse_int_beg{
        meta.has_int_header = 1;
        packet.extract(hdr.int_beg);
        meta.matadata_to_parse = hdr.int_beg.hop_ml;
        transition select(meta.matadata_to_parse){
            0: parse_ipv6;
            default: parse_int_end;
        }
    }
    state parse_int_end{
        packet.extract(hdr.int_end.next);
        meta.matadata_to_parse = meta.matadata_to_parse - 1;
        transition select(meta.matadata_to_parse){
            0: parse_ipv6;
            default: parse_int_end;
        }
    }
    state parse_ipv6{
        packet.extract(hdr.ipv6);
        transition select(meta.has_int_header){
            1: parse_srh_beg;
            default: accept;
        }
    }
    state parse_srh_beg{
        packet.extract(hdr.srh_beg);
        meta.segment_list_items_to_parse = hdr.srh_beg.segments_left;
        transition select(meta.segment_list_items_to_parse){
            0: accept;
            //in an incoming packet this value should never reach zero:
            //if it did, that would mean that there are no more segments in the SRH
            //that would mean, we got an empty SRH which is invalid, because the last switch
            //to edit its contents used the original IPv6 address and not the one in this header
            //and it also took the INT header out and put it after the IPv6
            default: parse_srh_end;
        }
    }
    state parse_srh_end{
        packet.extract(hdr.srh_end.next);
        meta.segment_list_items_to_parse = meta.segment_list_items_to_parse - 1;
        transition select(meta.segment_list_items_to_parse){
            0: accept;
            default: parse_srh_end;
        }
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

    action setEgress(bit<9> port){
        standard_metadata.egress_spec = port;
    }
    
    table forward{ //definiáljuk a táblát
        key = {
            meta.to_send_to_ipv6.Addr0: exact;
        }
        actions = {
          NoAction;
          setEgress;
        }
        size = 8;
        default_action = NoAction();
    }

    action addMetadata(bit<8> this_id){
        hdr.srh_end.pop_front(1);
        hdr.srh_beg.segments_left = hdr.srh_beg.segments_left - 1;
        meta.have_processed = 1;

        hdr.int_beg.hop_ml = hdr.int_beg.hop_ml + 1;
        hdr.int_end.push_front(1);
        hdr.int_end[0].setValid();
        if(hdr.int_beg.instruction_bitmap & 0b00000000001 != 0){
            hdr.int_end[0].switch_id = this_id;
        }
    }

    table add_our_telemetry{
        key = {
            hdr.srh_end[0].addr.Addr0: exact;
        }
        actions = {
            NoAction;
            addMetadata;
        }
        size = 1;
        default_action = NoAction();
    }

    apply {
        meta.ingress_timestamp = standard_metadata.ingress_global_timestamp;
        meta.have_processed = 0;
        if(meta.has_int_header == 1){
            //if there is an INT header, there MUST be a SRH too
            //we no longer need the first SRH segment list item as
            //we will just forward the packet in its direction
            add_our_telemetry.apply();
            
            //if hdr.srh_beg.segments_left is now 0, that means
            //we can convert the packet into a simple ETHERNET + IPv6 + INT + INT'S METADATA format
            if(hdr.srh_beg.segments_left == 0){
                meta.to_send_to_ipv6 = hdr.ipv6.dst;
                hdr.ethernet.ethertype = 16w0x86DD;
                hdr.ipv6_to_final_destination = hdr.ipv6;
                hdr.ipv6_to_final_destination.nextHdr = 253;
                hdr.ipv6.setInvalid();
                hdr.srh_beg.setInvalid();
                //hdr.int_beg.setInvalid(); //TODO: remove this if INT header's preamble is needed at the destination
            }else{
                meta.to_send_to_ipv6 = hdr.srh_end[0].addr;
            }
        }else{
            meta.to_send_to_ipv6 = hdr.ipv6.dst;
        }
        forward.apply(); //csak alkalmazzuk a táblát
        if(meta.have_processed == 1){
            if(hdr.int_beg.instruction_bitmap & 0b00000000010 != 0){
                hdr.int_end[0].in_port_id = standard_metadata.ingress_port;
            }
            if(hdr.int_beg.instruction_bitmap & 0b00000000100 != 0){
                hdr.int_end[0].e_port_id = standard_metadata.egress_spec;
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { 
        if(meta.have_processed == 1){
            if(hdr.int_beg.instruction_bitmap & 0b00000001000 != 0){
                hdr.int_end[0].processed_time = standard_metadata.egress_global_timestamp - meta.ingress_timestamp;
            }
        }
     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {

    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet); //emittáljuk a megadott fejlécet
        packet.emit(hdr.ipv6_to_final_destination);
        packet.emit(hdr.int_beg);
        packet.emit(hdr.int_end);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.srh_beg);
        packet.emit(hdr.srh_end);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
