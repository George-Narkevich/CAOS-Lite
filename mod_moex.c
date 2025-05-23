#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/socket.h>

#define API_HOST "iss.moex.com"
#define API_PORT 80
#define UPDATE_INTERVAL 5000 /* 5 seconds */

static struct task_struct *update_thread;
static char *stock_data;
static DEFINE_SPINLOCK(data_lock);

static const char *http_req = 
    "GET /iss/engines/stock/markets/shares/boards/TQBR/securities.json HTTP/1.1\r\n"
    "Host: iss.moex.com\r\n"
    "Connection: close\r\n\r\n";

static void parse_response(const char *response) {
    const char *ptr = strstr(response, "\"LAST\":");
    if (ptr) {
        spin_lock(&data_lock);
        sscanf(ptr, "\"LAST\":\"%[^\"]", stock_data);
        spin_unlock(&data_lock);
    }
}

static int update_worker(void *data) {
    struct socket *sock;
    struct sockaddr_in s_addr;
    int ret;
    char buf[4096];

    while (!kthread_should_stop()) {
        ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
        if (ret < 0) {
            printk(KERN_ERR "Socket creation failed\n");
            goto sleep;
        }

        memset(&s_addr, 0, sizeof(s_addr));
        s_addr.sin_family = AF_INET;
        s_addr.sin_port = htons(API_PORT);
        s_addr.sin_addr.s_addr = in_aton("217.118.95.66");

        ret = sock->ops->connect(sock, (struct sockaddr *)&s_addr, sizeof(s_addr), 0);
        if (ret < 0) {
            printk(KERN_ERR "Connection failed\n");
            sock_release(sock);
            goto sleep;
        }

        ret = kernel_sendmsg(sock, &msghdr, &iov, 1, strlen(http_req));
        if (ret < 0) {
            printk(KERN_ERR "Send failed\n");
            sock_release(sock);
            goto sleep;
        }

        memset(buf, 0, sizeof(buf));
        ret = kernel_recvmsg(sock, &msghdr, &iov, 1, sizeof(buf), 0);
        if (ret > 0) {
            parse_response(buf);
        }

        sock_release(sock);

sleep:
        msleep_interruptible(UPDATE_INTERVAL);
    }
    return 0;
}

static ssize_t moex_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    spin_lock(&data_lock);
    size_t len = strlen(stock_data);
    ssize_t ret = simple_read_from_buffer(buf, count, ppos, stock_data, len);
    spin_unlock(&data_lock);
    return ret;
}

static struct file_operations proc_fops = {
    .owner = THIS_MODULE,
    .read = moex_read,
};

static int __init moex_init(void) {
    stock_data = kmalloc(256, GFP_KERNEL);
    strcpy(stock_data, "No data");

    proc_create("moex_stocks", 0444, NULL, &proc_fops);

    update_thread = kthread_run(update_worker, NULL, "moex_updater");
    
    return 0;
}

static void __exit moex_exit(void) {
    kthread_stop(update_thread);
    kfree(stock_data);
    remove_proc_entry("moex_stocks", NULL);
}

module_init(moex_init);
module_exit(moex_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
