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

SEC("xdp_decap")                                     
int decap(struct xdp_md* ctx) {                           
    void *old_data = (void *)(long)ctx->data;                                    
    void *old_data_end = (void *)(long)ctx->data_end;
    struct ethhdr *old_eth = old_data;                                               

    if (old_data + sizeof(struct ethhdr) > old_data_end)                             
        return XDP_PASS;

    // only encap IP packet
    if (old_eth->h_proto != bpf_ntohs(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr *old_iph = old_data + sizeof(struct ethhdr);                     
    if (old_data + sizeof(struct ethhdr) + sizeof(struct iphdr) > old_data_end) {
        bpf_printk("error");
        return XDP_DROP;
    }

    // only decap UDP packet
    if (old_iph->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }

    struct udphdr* old_udph = old_data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (old_data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > old_data_end) {
        bpf_printk("error");
        return XDP_DROP;
    }

    bpf_printk("Source: %d, Dest: %d", bpf_ntohs(old_udph->source), bpf_ntohs(old_udph->dest));

    if (bpf_ntohs(old_udph->source) == ENCAP_PORT && bpf_ntohs(old_udph->dest) == ENCAP_PORT) {
        // Decap
        bpf_printk("Received packet. Decap...");
        if (bpf_xdp_adjust_head(ctx, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))) {
            // fail to decap head
            bpf_printk("error");
            return XDP_DROP;
        }

        // assume veth-1 ifindex = 3
        int ret = bpf_redirect(3, 0);

        if (ret != XDP_REDIRECT) {
            bpf_printk("decap redirect %d", ret);
        }

        bpf_printk("Redirect...");

        return ret;
    }
    else {
        // normal UDP packet.
        return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";