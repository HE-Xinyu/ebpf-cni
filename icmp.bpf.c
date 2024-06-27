#include <linux/bpf.h>                           
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include "common.h"

unsigned char lookup_protocol(struct xdp_md *ctx)
{
   unsigned char protocol = 0;

   void *data = (void *)(long)ctx->data;                                    
   void *data_end = (void *)(long)ctx->data_end;
   struct ethhdr *eth = data;                                               
   if (data + sizeof(struct ethhdr) > data_end)                             
       return 0;

   // Check that it's an IP packet
   if (bpf_ntohs(eth->h_proto) == ETH_P_IP)                                 
   {
       // Return the protocol of this packet
       // 1 = ICMP
       // 6 = TCP
       // 17 = UDP       
       struct iphdr *iph = data + sizeof(struct ethhdr);                     
       if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) <= data_end) 
           protocol = iph->protocol;                                        
   }
   return protocol;
}

unsigned char lookup_icmp_protocol(struct xdp_md* ctx) {
    // not icmp
    if (lookup_protocol(ctx) != IPPROTO_ICMP) {
        return NR_ICMP_TYPES + 1;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct icmphdr* icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
        return NR_ICMP_TYPES + 1;
    }

    return icmph->type;
}

SEC("xdp_icmp")
int log_icmp(struct xdp_md* ctx) {
    unsigned char icmp_type = lookup_icmp_protocol(ctx);

    if (icmp_type == ICMP_ECHO) {
        bpf_printk("Received ICMP ECHO");
    }
    else if (icmp_type == ICMP_ECHOREPLY) {
        bpf_printk("Received ICMP ECHO REPLY");
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";