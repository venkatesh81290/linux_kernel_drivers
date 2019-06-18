#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


/*Network packet filter structure*/
struct nf_rule {
	unsigned char in_out;		//0: neither in nor out, 1: in, 2: out
	unsigned int src_ip;
	unsigned int src_netmask;
	unsigned int src_port;
	unsigned int dest_ip;
	unsigned int dest_netmask;
	unsigned int dest_port;
	unsigned char proto;		//0: all, 1: tcp, 2: udp
	unsigned char action;		//0: for block, 1: for unblock
	struct list_head list;
};
 
static struct nf_rule policy_list;
 
static struct nf_hook_ops nfho_in, nfho_out;
 
unsigned int port_str_to_int(char *port_str) {
	unsigned int port = 0;    
	int i = 0;

	if (port_str==NULL) {
		return 0;
	}

	while (port_str[i]!='\0') {
		port = port*10 + (port_str[i]-'0');
		++i;
	}
	return port;
}
 
unsigned int ip_str_to_hl(char *ip_str) {
    /*convert the string to byte array first, e.g.: from "131.132.162.25" to [131][132][162][25]*/
	unsigned char ip_array[4];
	int i = 0;
	unsigned int ip = 0;

	if (ip_str==NULL) {
		return 0; 
	}

	memset(ip_array, 0, 4);

	while (ip_str[i]!='.') {
		ip_array[0] = ip_array[0]*10 + (ip_str[i++]-'0');
	}
	++i;

	while (ip_str[i]!='.') {
		ip_array[1] = ip_array[1]*10 + (ip_str[i++]-'0');
	}
	++i;

	while (ip_str[i]!='.') {
		ip_array[2] = ip_array[2]*10 + (ip_str[i++]-'0');
	}
	++i;

	while (ip_str[i]!='\0') {
		ip_array[3] = ip_array[3]*10 + (ip_str[i++]-'0');
	}

	/*convert from byte array to host long integer format*/
	ip = (ip_array[0] << 24);
	ip = (ip | (ip_array[1] << 16));
	ip = (ip | (ip_array[2] << 8));
	ip = (ip | ip_array[3]);
//	printk(KERN_INFO "ip_str_to_hl convert %s to %u\n", ip_str, ip);
	return ip;
}
 
/*check the two input IP addresses, see if they match, only the first few bits (masked bits) are compared*/
bool check_ip(unsigned int ip, unsigned int ip_rule, unsigned int mask) {
	unsigned int tmp = ntohl(ip);    //network to host long
	int cmp_len = 32;
	int i = 0, j = 0;

	printk(KERN_INFO "compare ip: %u <=> %u\n", tmp, ip_rule);

	if (mask != 0) {
		cmp_len = 0;
		for (i = 0; i < 32; ++i) {
			if (mask & (1 << (32-1-i)))
				cmp_len++;
			else
 				break;
		}
	}

	/*compare the two IP addresses for the first cmp_len bits*/
	for (i = 31, j = 0; j < cmp_len; --i, ++j) {
		if ((tmp & (1 << i)) != (ip_rule & (1 << i))) {
			printk(KERN_INFO "ip compare: %d bit doesn't match\n", (32-i));
			return false;
		}
	}
	return true;
}

unsigned int hook_func_out(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct list_head *p;
	struct nf_rule *a_rule;
	int i = 0;
 
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;
 
	if (ip_header->protocol==17) {
		udp_header = (struct udphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(udp_header->source);
	} else if (ip_header->protocol == 6) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(tcp_header->source);
		dest_port = (unsigned int)ntohs(tcp_header->dest);
	}
 
	printk(KERN_INFO "OUT packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 
	printk(KERN_DEBUG "IP addres = %pI4  DEST = %pI4\n", &src_ip, &dest_ip);

	list_for_each(p, &policy_list.list) {
		i++;
		a_rule = list_entry(p, struct nf_rule, list);

		printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);

		if (a_rule->in_out != 2) {
			printk(KERN_INFO "rule %d (a_rule->in_out: %u) not match: out packet, rule doesn't specify as out\n", i, a_rule->in_out);
			continue;
		} else {
			if ((a_rule->proto==1) && (ip_header->protocol != 6)) {
				printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
				continue;
			} else if ((a_rule->proto==2) && (ip_header->protocol != 17)) {
				printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
				continue;
			}
 
			if (a_rule->src_ip != 0) {
				if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
					printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
					continue;
				}
			}
 
			if (a_rule->dest_ip != 0) {
				if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
					printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);
					continue;
				}
			}

			if (a_rule->src_port != 0) {
				if (src_port!=a_rule->src_port) {
					printk(KERN_INFO "rule %d not match: src port dismatch\n", i);
					continue;
				}
			}
 
			if (a_rule->dest_port != 0) {
				if (dest_port!=a_rule->dest_port) {
					printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
					continue;
				}
			}
 
			if (a_rule->action==0) {
				printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			} else {
				printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_ACCEPT;
			}
		}
	}
	printk(KERN_INFO "no matching is found, accept the packet\n");
	printk(KERN_INFO "---------------------------------------\n");
	return NF_ACCEPT;            
}
 
unsigned int hook_func_in(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *)) {
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	struct udphdr *udp_header;
	struct tcphdr *tcp_header;
	struct list_head *p;
	struct nf_rule *a_rule;
	int i = 0;

	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	unsigned int src_port = 0;
	unsigned int dest_port = 0;
	printk(KERN_DEBUG "IP addres = %pI4  DEST = %pI4\n", &src_ip, &dest_ip);

	if (ip_header->protocol==17) {
		udp_header = (struct udphdr *)(skb_transport_header(skb)+20);
		src_port = (unsigned int)ntohs(udp_header->source);
		dest_port = (unsigned int)ntohs(udp_header->dest);
	} else if (ip_header->protocol == 6) {
		tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20);
		src_port = (unsigned int)ntohs(tcp_header->source);
		dest_port = (unsigned int)ntohs(tcp_header->dest);
	}
 
	printk(KERN_INFO "IN packet info: src ip: %u, src port: %u; dest ip: %u, dest port: %u; proto: %u\n", src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 

	list_for_each(p, &policy_list.list) {
		i++;
		a_rule = list_entry(p, struct nf_rule, list);

		printk(KERN_INFO "rule %d: a_rule->in_out = %u; a_rule->src_ip = %u; a_rule->src_netmask=%u; a_rule->src_port=%u; a_rule->dest_ip=%u; a_rule->dest_netmask=%u; a_rule->dest_port=%u; a_rule->proto=%u; a_rule->action=%u\n", i, a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);

		if (a_rule->in_out != 1) {
			printk(KERN_INFO "rule %d (a_rule->in_out:%u) not match: in packet, rule doesn't specify as in\n", i, a_rule->in_out);
			continue;
		} else {
			if ((a_rule->proto==1) && (ip_header->protocol != 6)) {
				printk(KERN_INFO "rule %d not match: rule-TCP, packet->not TCP\n", i);
				continue;
			} else if ((a_rule->proto==2) && (ip_header->protocol != 17)) {
				printk(KERN_INFO "rule %d not match: rule-UDP, packet->not UDP\n", i);
				continue;
			}

			if (a_rule->src_ip != 0) {
				if (!check_ip(src_ip, a_rule->src_ip, a_rule->src_netmask)) {
					printk(KERN_INFO "rule %d not match: src ip mismatch\n", i);
					continue;
				}
			}

			if (a_rule->dest_ip != 0) {
				if (!check_ip(dest_ip, a_rule->dest_ip, a_rule->dest_netmask)) {
					printk(KERN_INFO "rule %d not match: dest ip mismatch\n", i);                  
					continue;
				}
			}

			if (a_rule->src_port != 0) {
				if (src_port!=a_rule->src_port) {
					printk(KERN_INFO "rule %d not match: src port mismatch\n", i);
					continue;
				}
			}

			if (a_rule->dest_port != 0) {
				if (dest_port!=a_rule->dest_port) {
					printk(KERN_INFO "rule %d not match: dest port mismatch\n", i);
					continue;
				}
			}
 
			if (a_rule->action==0) {
				printk(KERN_INFO "a match is found: %d, drop the packet\n", i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_DROP;
			} else {
				printk(KERN_INFO "a match is found: %d, accept the packet\n", i);
				printk(KERN_INFO "---------------------------------------\n");
				return NF_ACCEPT;
			}
		}
	}
	printk(KERN_INFO "no matching is found, accept the packet\n");
	printk(KERN_INFO "---------------------------------------\n");
	return NF_ACCEPT;                
}
 
void add_a_rule(
        unsigned char in_out,
        char *src_ip,
        char *src_port,
        char *src_netmask,
        char *dest_ip,
        char *dest_port,
        char *dest_netmask,
        unsigned char proto,
        unsigned char action ) {

	struct nf_rule* a_rule;

	a_rule = kmalloc(sizeof(*a_rule), GFP_KERNEL);

	if (a_rule == NULL) {
		printk(KERN_INFO "error: cannot allocate memory for a_new_rule\n");
		return;
	}

	a_rule->in_out = in_out;
	a_rule->src_ip = ip_str_to_hl(src_ip);
	a_rule->src_netmask = ip_str_to_hl(src_netmask);
	a_rule->src_port = port_str_to_int(src_port);
	a_rule->dest_ip = ip_str_to_hl(dest_ip);
	a_rule->dest_netmask = ip_str_to_hl(dest_netmask);
	a_rule->dest_port = port_str_to_int(dest_port);
	a_rule->proto = proto;
	a_rule->action = action;

	printk(KERN_INFO "add_a_rule: in_out=%u, src_ip=%u, src_netmask=%u, src_port=%u, dest_ip=%u, dest_netmask=%u, dest_port=%u, proto=%u, action=%u\n", a_rule->in_out, a_rule->src_ip, a_rule->src_netmask, a_rule->src_port, a_rule->dest_ip, a_rule->dest_netmask, a_rule->dest_port, a_rule->proto, a_rule->action);

	INIT_LIST_HEAD(&(a_rule->list));

	list_add_tail(&(a_rule->list), &(policy_list.list));
}
 
/* Initialization routine */
static int __init nf_hook_init(void) {
	printk(KERN_INFO "initialize kernel module\n");

	INIT_LIST_HEAD(&(policy_list.list));
 
	/* Fill in the hook structure for incoming packet hook*/
    nfho_in.hook = hook_func_in;
    nfho_in.hooknum = NF_INET_LOCAL_IN;
    nfho_in.pf = PF_INET;
    nfho_in.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho_in);
 
	/* Fill in the hook structure for outgoing packet hook*/
	nfho_out.hook = hook_func_out;
	nfho_out.hooknum = NF_INET_PRE_ROUTING;
	nfho_out.pf = PF_INET;
	nfho_out.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho_out);


	/*this part of code is for testing purpose*/
    /* Incoming packet rule */
	add_a_rule(2, "175.41.132.108", NULL, "255.255.0.0", NULL, NULL, NULL, 6, 0);
	add_a_rule(2, "10.4.103.110", NULL, "255.255.0.0", "10.4.103.110", NULL, "255.255.0.0", 6, 0);
    /* Outgoing packet rule */
	add_a_rule(2, NULL, NULL, NULL, "10.187.52.234", NULL, "255.255.0.0", 6, 0);
	add_a_rule(2, NULL, NULL, NULL, "175.41.132.108", NULL, "255.255.0.0", 6, 0);

	return 0;
}
 
/* Cleanup routine */
static void __exit nf_hook_exit(void) {
    struct list_head *p, *q;
    struct nf_rule *a_rule;

    nf_unregister_hook(&nfho_in);
    nf_unregister_hook(&nfho_out);

    printk(KERN_INFO "free policy list\n");

    list_for_each_safe(p, q, &policy_list.list) {
        printk(KERN_INFO "free one\n");
        a_rule = list_entry(p, struct nf_rule, list);
        list_del(p);
        kfree(a_rule);
    }
    printk(KERN_INFO "kernel module unloaded.\n");
}

module_init(nf_hook_init);
module_exit(nf_hook_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Venkatesh Parthasarathy <venkatesh81290@gmail.com>");
MODULE_DESCRIPTION("Sample Netfilter Hook driver");
