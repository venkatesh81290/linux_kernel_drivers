#include <linux/module.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_USER 31

struct sock *nl_sk = NULL;

static void nl_rcv(struct sk_buff *skb)
{

    struct nlmsghdr *nlh;
    pid_t pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "Hello from kernel";
    int res;

    printk(KERN_INFO "Entering: %s\n", __FUNCTION__);

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid; /*pid of sending process */
    printk(KERN_INFO "Recieved [PID: %d]: %s\n", pid, (char *)nlmsg_data(nlh));

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    }
    
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    printk(KERN_INFO "Sending: %s\n", msg);
    res = nlmsg_unicast(nl_sk, skb_out, pid);

    if (res < 0)
        printk(KERN_INFO "Error while sending bak to user\n");
}

static struct netlink_kernel_cfg nl_cfg = {
    .input  = nl_rcv,
};

static int __init nl_sock_init(void)
{

    printk("Entering: %s\n", __FUNCTION__);
    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &nl_cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit nl_sock_exit(void)
{

    printk(KERN_INFO "exiting hello module\n");
    netlink_kernel_release(nl_sk);
}

module_init(nl_sock_init);
module_exit(nl_sock_exit);

MODULE_LICENSE("GPL");
