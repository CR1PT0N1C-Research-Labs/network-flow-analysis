#include "monlib.h"
#include <stdint.h>      
#include <stddef.h>      
#include <string.h>      
#include <arpa/inet.h>   
#include <linux/if_ether.h> 
#include <linux/ip.h>      
#include <linux/tcp.h>      
#include <linux/udp.h>      

static struct monlib_stats packetStats;
static unsigned int totalBytes = 0;
static unsigned int tcp_rsts = 0;

struct TFlow {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
    unsigned int packets;
    unsigned int bytes;
};

static struct TFlow flowTable[50];
static int flowCnt = 0;

void monlib_reset(struct monlib_ctx *ctx) {
    memset(&packetStats, 0, sizeof(struct monlib_stats));
    memset(&flowTable, 0, sizeof(flowTable));
    totalBytes = 0;
    flowCnt = 0;
    packetStats.min_dst_port = 0xFFFF; 

    tcp_rsts = 0;
}

int monlib_init(struct monlib_ctx *ctx)
{
    ctx->os_ops.printf("Monlib Init\n");
    monlib_reset(ctx);
    return 0;
}

int monlib_process(struct monlib_ctx *ctx, const void *packet, const unsigned int packet_len) {
    if (packet_len < ETH_HLEN) return 0;

    packetStats.packets++;
    totalBytes += packet_len;

    const struct ethhdr *eth = (const struct ethhdr *)packet;
    uint16_t eth_proto = ntohs(eth->h_proto);
    const unsigned char *l3_data = (const unsigned char *)packet + ETH_HLEN;
    unsigned int l3_len = packet_len - ETH_HLEN;

    uint8_t l4_proto = 0;
    const unsigned char *l4_data = NULL;
    unsigned int l4_len = 0;
    uint32_t src_ip = 0, dst_ip = 0;

    if (eth_proto == ETH_P_IP) {
        packetStats.ipv4_packets++;
        if (l3_len < sizeof(struct iphdr)) return 0;
        const struct iphdr *ip4 = (const struct iphdr *)l3_data;
        unsigned int ip_hdr_len = ip4->ihl * 4;
        if (l3_len < ip_hdr_len) return 0;

        src_ip = ip4->saddr;
        dst_ip = ip4->daddr;
        l4_proto = ip4->protocol;
        l4_data = l3_data + ip_hdr_len;
        l4_len = l3_len - ip_hdr_len;
    } else if (eth_proto == ETH_P_IPV6) {
        packetStats.ipv6_packets++;
        return 0; 
    } else {
        return 0;
    }

    uint16_t src_port = 0, dst_port = 0;

    if (l4_proto == IPPROTO_TCP) {
        packetStats.tcp_packets++;
        if (l4_len < sizeof(struct tcphdr)) return 0;
        const struct tcphdr *tcp = (const struct tcphdr *)l4_data;
        
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);

        if(tcp->syn) packetStats.tcp_syns++;
        if(tcp->fin) packetStats.tcp_fins++;
        if(tcp->rst) tcp_rsts++;

        if(ntohs(tcp->syn)) packetStats.tcp_syns++;
        if(ntohs(tcp->fin)) packetStats.tcp_fins++;
        
    } else if (l4_proto == IPPROTO_UDP) {
        packetStats.udp_packets++;
        if (l4_len < sizeof(struct udphdr)) return 0;
        const struct udphdr *udp = (const struct udphdr *)l4_data;
        
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    } else {
        return 0; 
    }

    if(src_port > packetStats.max_src_port) packetStats.max_src_port = src_port;
    if(dst_port < packetStats.min_dst_port) packetStats.min_dst_port = dst_port;

    int found = 0;
    for(int i = 0; i < flowCnt; i++) {
        if((flowTable[i].src_ip == src_ip && flowTable[i].dst_ip == dst_ip) || 
           (flowTable[i].src_ip == dst_ip && flowTable[i].dst_ip == src_ip)) {
            
            flowTable[i].packets++;
            flowTable[i].bytes += packet_len;
            found = 1; 
            break; 
        }
    }

    if(!found && flowCnt < 50) {
        flowTable[flowCnt].src_ip = src_ip;
        flowTable[flowCnt].dst_ip = dst_ip;
        flowTable[flowCnt].src_port = src_port;
        flowTable[flowCnt].dst_port = dst_port;
        flowTable[flowCnt].proto = l4_proto;
        flowTable[flowCnt].packets = 1;
        flowTable[flowCnt].bytes = packet_len;
        flowCnt++;
    }

    // --- DETEKCE SYN FLOOD ÚTOKU ---
    unsigned int closed = packetStats.tcp_fins + tcp_rsts;
    
    if (closed == 0) {
        closed = 1;
    }

    // ochrana aby byla detekce spuštěna až při dostatečně velkém vzorku
    if (packetStats.tcp_syns > 50) {
        unsigned int ratio = packetStats.tcp_syns / closed;

        if (ratio > 5) {
            ctx->os_ops.printf("ALERT: SYN Flood detected! SYN: %u, FIN+RST: %u, Pomer: %u\n", packetStats.tcp_syns, closed, ratio);
            
            packetStats.tcp_syns = 0;
            packetStats.tcp_fins = 0;
            tcp_rsts = 0;
        }
    }

    return 0;
}

struct monlib_stats monlib_get_stats(struct monlib_ctx *ctx) {
    if (packetStats.packets > 0) {
        packetStats.avr_byte_len = totalBytes / packetStats.packets;
    }

    packetStats.flows = flowCnt;

    unsigned int avgFlowPackets = 0; 
    unsigned int avgFlowBytes = 0;   

    for(int i = 0; i < flowCnt; i++){
        avgFlowPackets += flowTable[i].packets;
        avgFlowBytes += flowTable[i].bytes;
    }

    if (flowCnt > 0) {
        packetStats.avr_flow_p_len = avgFlowPackets / flowCnt;
        packetStats.avr_flow_b_len = avgFlowBytes / flowCnt;
    }

    return packetStats;
}

void monlib_cleanup(struct monlib_ctx *ctx)
{

}
