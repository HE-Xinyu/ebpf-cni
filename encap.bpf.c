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
// #include "vmlinux.h"

#define NODE_IP_ADDRESS(x) (unsigned int)(10 + (1 << 8) + (0 << 16) + (x << 24))

#define BACKEND 5
#define LB 6

#define NODE_1 1

#ifdef NODE_1
unsigned char CURR_NODE_MAC[6] = {0x00, 0x22, 0x48, 0x57, 0xf8, 0x20};
unsigned char OTHER_NODE_MAC[6] = {0x00, 0x22, 0x48, 0x59, 0x9e, 0xbf};
unsigned char OTHER_VETH_MAC[6] = {0x12, 0x64, 0xc7, 0xc3, 0x6f, 0x83};
unsigned char OTHER_POD_MAC[6] = {0x6a, 0x79, 0xae, 0xe7, 0x6d, 0xb8};
unsigned int CURR_NODE_IP = NODE_IP_ADDRESS(6);
unsigned int OTHER_NODE_IP = NODE_IP_ADDRESS(5);
#else
unsigned char CURR_NODE_MAC[6] = {0x00, 0x22, 0x48, 0x59, 0x9e, 0xbf};
unsigned char OTHER_NODE_MAC[6] = {0x00, 0x22, 0x48, 0x57, 0xf8, 0x20};
unsigned char OTHER_VETH_MAC[6] = {0x66, 0x74, 0x97, 0xde, 0xd4, 0xad};
unsigned char OTHER_POD_MAC[6] = {0xfe, 0x9b, 0xb0, 0x31, 0x95, 0x60};
unsigned int CURR_NODE_IP = NODE_IP_ADDRESS(5);
unsigned int OTHER_NODE_IP = NODE_IP_ADDRESS(6);

#endif


unsigned char CLIENT_MAC[6];
unsigned int CLIENT_IP;

unsigned short id = 0;

struct custom_encap_hdr {
    struct ethhdr ehdr;
    struct iphdr ihdr;
};

static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

#define MAX_UDP_SIZE 1480

/* All credit goes to FedeParola from https://github.com/iovisor/bcc/issues/2463 */
__attribute__((__always_inline__))
static inline __u16 caludpcsum(struct iphdr *iph, struct udphdr *udph, void *data_end)
{
    udph->check = 0;
    __u32 csum_buffer = 0;
    __u16 *buf = (void *)udph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += udph->len;

    // Compute checksum on udp header + payload
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) 
    {
        if ((void *)(buf + 1) > data_end) 
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) 
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}


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
    if (lookup_protocol(ctx) != 1) {
        return 6;
    }

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct icmphdr* icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
        return 6;
    }

    return icmph->type;
}

SEC("xdp_encap")                                     
int encap(struct xdp_md* ctx) {                           
    bpf_printk("Starting encap 1...");
    void *old_data = (void *)(long)ctx->data;                                    
    void *old_data_end = (void *)(long)ctx->data_end;
    struct ethhdr *old_eth = old_data;                                               

    if (old_data + sizeof(struct ethhdr) > old_data_end) {
        bpf_printk("Not eth");
        return XDP_PASS;
    }

    // only encap IP packet
    if (bpf_ntohs(old_eth->h_proto) != ETH_P_IP) {
        bpf_printk("Not IP: 0x%x", bpf_ntohs(old_eth->h_proto));
        return XDP_PASS;
    }

    bpf_printk("Starting encap...");

    for (int i = 0; i < 6; i++) {
        old_eth->h_dest[i] = OTHER_POD_MAC[i];
        old_eth->h_source[i] = OTHER_VETH_MAC[i];
    }

    struct iphdr *old_iph = old_data + sizeof(struct ethhdr);                     
    if (old_data + sizeof(struct ethhdr) + sizeof(struct iphdr) > old_data_end) {
        bpf_printk("error");
        return XDP_DROP;
    }

    if (bpf_xdp_adjust_head(ctx, 0 - sizeof(struct ethhdr) - sizeof(struct iphdr) - sizeof(struct udphdr))) {
        // fail to expand head
        bpf_printk("error");
        return XDP_DROP;
    }

    void* data = (void *)(long)ctx->data;                                    
    void* data_end = (void *)(long)ctx->data_end;

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end) {
        bpf_printk("error");
        return XDP_DROP;
    }

    struct ethhdr* ehdr = data;
    struct iphdr* ihdr = data + sizeof(struct ethhdr);
    struct udphdr* uhdr = data + sizeof(struct ethhdr) + sizeof(struct iphdr);

    // 1. ethernet header encap
    ehdr->h_proto = bpf_htons(ETH_P_IP);
    int i = 0;
    for (i = 0; i < 6; i++) {
        ehdr->h_source[i] = CURR_NODE_MAC[i];
        ehdr->h_dest[i] = OTHER_NODE_MAC[i];
    }

    // 2. ip header encap
    // ip already htons
    ihdr->saddr = CURR_NODE_IP;
    ihdr->daddr = OTHER_NODE_IP;
    ihdr->protocol = IPPROTO_UDP;
    // assume ip header is fixed 20 bytes
    ihdr->tot_len = bpf_htons(20 + sizeof(struct udphdr) + (old_data_end - old_data));
    ihdr->version = 4;
    ihdr->ihl = 5;
    ihdr->id = bpf_htons(id);
    id = (id + 1) & 0xffff;

    ihdr->ttl = 64;
    ihdr->check = iph_csum(ihdr);

    // 3. udp header encap
    uhdr->source = bpf_htons(ENCAP_PORT);
    uhdr->dest = bpf_htons(ENCAP_PORT);
    uhdr->len = bpf_htons(sizeof(struct udphdr) + (old_data_end - old_data));
    uhdr->check = caludpcsum(ihdr, uhdr, data_end);

    bpf_printk("Encap done");
    // return XDP_PASS;
    // assume the eth0 with index 2
    int ret = bpf_redirect(2, 0);

    if (ret != XDP_REDIRECT) {
        bpf_printk("Error redirect %d", ret);
    }

    return ret;


    




    // if (data + sizeof(struct ethhdr) > data_end)                             
    //    return XDP_PASS;
    // if (protocol == 0) // ICMP Reply
    // {
    //     bpf_printk("Hello ping reply");
    //     // bpf_printk("%x %x", eth->h_source[0], eth->h_source[5]);
    //     bpf_printk("Src Mac 1: %x %x %x",
    //         eth->h_source[0],
    //         eth->h_source[1],
    //         eth->h_source[2]);
    //     bpf_printk("Src Mac 2: %x %x %x",
    //         eth->h_source[3],
    //         eth->h_source[4],
    //         eth->h_source[5]);
    //     bpf_printk("Dest Mac 1: %x %x %x",
    //         eth->h_dest[0],
    //         eth->h_dest[1],
    //         eth->h_dest[2]);
    //     bpf_printk("Dest Mac 2: %x %x %x",
    //         eth->h_dest[3],
    //         eth->h_dest[4],
    //         eth->h_dest[5]);
    // }
    // else if (protocol == 8) {
    //     bpf_printk("Hello ping request");
    //     bpf_printk("Src Mac 1: %x %x %x",
    //         eth->h_source[0],
    //         eth->h_source[1],
    //         eth->h_source[2]);
    //     bpf_printk("Src Mac 2: %x %x %x",
    //         eth->h_source[3],
    //         eth->h_source[4],
    //         eth->h_source[5]);
    //     bpf_printk("Dest Mac 1: %x %x %x",
    //         eth->h_dest[0],
    //         eth->h_dest[1],
    //         eth->h_dest[2]);
    //     bpf_printk("Dest Mac 2: %x %x %x",
    //         eth->h_dest[3],
    //         eth->h_dest[4],
    //         eth->h_dest[5]);
    //     // bpf_printk("Src Mac: %x:%x:%x:%x:%x:%x",
    //     //     eth->h_source[0],
    //     //     eth->h_source[1],
    //     //     eth->h_source[2],
    //     //     eth->h_source[3],
    //     //     eth->h_source[4],
    //     //     eth->h_source[5]);
    //     // bpf_printk("Dst Mac: %x:%x:%x:%x:%x:%x", 
    //     //     eth->h_dest[0], 
    //     //     eth->h_dest[1], 
    //     //     eth->h_dest[2], 
    //     //     eth->h_dest[3], 
    //     //     eth->h_dest[4], 
    //     //     eth->h_dest[5]);
    // }
    // return XDP_PASS;
//     unsigned char BACKEND_MAC[6] = {0x00, 0x22, 0x48, 0x59, 0x9e, 0xbf};
//     unsigned char LB_MAC[6] = {0x00, 0x22, 0x48, 0x57, 0xf8, 0x20};
//     void *data = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;

//     struct ethhdr *eth = data;
//     if (data + sizeof(struct ethhdr) > data_end)
//         return XDP_ABORTED;

//     if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
//         return XDP_PASS;

//     struct iphdr *iph = data + sizeof(struct ethhdr);
//     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
//         return XDP_ABORTED;

//     if (iph->protocol != IPPROTO_TCP)               
//         return XDP_PASS;

//     // parse TCP

//     struct tcphdr* tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
//     if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
//         bpf_printk("TCP header error");
//         return XDP_ABORTED;
//     }


//     if (bpf_ntohs(tcph->dest) == 8080) {
//         if (iph->saddr == NODE_IP_ADDRESS(BACKEND)) {
//             // TODO: transfer back to client
//         }

//         if (bpf_get_prandom_u32() % 2) {
//             // Local
//             return XDP_PASS;
//         }
//         iph->daddr = NODE_IP_ADDRESS(BACKEND);
//         iph->saddr = NODE_IP_ADDRESS(LB);
//         eth->h_source = 

//         iph->check = iph_csum(iph);
//         return XDP_TX;
//     }

//     return XDP_PASS;

//     if (iph->saddr == NODE_IP_ADDRESS(CLIENT))           
//     {
//         char be = BACKEND_A;                        
//         if (bpf_get_prandom_u32() % 2)                
//             be = BACKEND_B;

//         iph->daddr = NODE_IP_ADDRESS(be);                
//         eth->h_dest[5] = be;
//     }
//     else
//     {
//         iph->daddr = NODE_IP_ADDRESS(CLIENT);            
//         eth->h_dest[5] = CLIENT;
//     }
//     iph->saddr = NODE_IP_ADDRESS(LB);                    
//     eth->h_source[5] = LB;

//     iph->check = iph_csum(iph);                     

//     return XDP_TX;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";