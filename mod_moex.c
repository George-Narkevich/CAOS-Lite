#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/tcp.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/uaccess.h>

#define API_HOST       "217.118.95.66"
#define API_PORT       80
#define UPDATE_INTERVAL 5000

static struct task_struct *update_thread;
static char           *stock_data;
static DEFINE_SPINLOCK(data_lock);

static const char *http_req =
    "GET /iss/engines/stock/markets/shares/boards/TQBR/securities.json "
    "HTTP/1.1\r\n"
    "Host: iss.moex.com\r\n"
    "Connection: close\r\n\r\n";

static void parse_response(const char *response)
{
    const char *ptr = strstr(response, "\"LAST\":");
    if (ptr) {
        spin_lock(&data_lock);
        sscanf(ptr, "\"LAST\":\"%255[^\"]", stock_data);
        spin_unlock(&data_lock);
    }
}

static int update_worker(void *data)
{
    struct socket   *sock;
    struct sockaddr_in s_addr;
    int               ret;
    char              buf[4096];

    while (!kthread_should_stop()) {
        ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
        if (ret < 0) {
            printk(KERN_ERR "moex: socket creation failed (%d)\n", ret);
            goto sleep;
        }

        memset(&s_addr, 0, sizeof(s_addr));
        s_addr.sin_family = AF_INET;
        s_addr.sin_port   = htons(API_PORT);
        s_addr.sin_addr.s_addr = in_aton(API_HOST);

        ret = sock->ops->connect(sock, (struct sockaddr *)&s_addr,
                                 sizeof(s_addr), 0);
        if (ret < 0) {
            printk(KERN_ERR "moex: connect failed (%d)\n", ret);
            sock_release(sock);
            goto sleep;
        }

        {
            struct msghdr msg = { .msg_flags = 0 };
            struct kvec   iov = {
                .iov_base = (void *)http_req,
                .iov_len  = strlen(http_req)
            };
            ret = kernel_sendmsg(sock, &msg, &iov, 1, iov.iov_len);
            if (ret < 0) {
                printk(KERN_ERR "moex: sendmsg failed (%d)\n", ret);
                sock_release(sock);
                goto sleep;
            }

            memset(buf, 0, sizeof(buf));
            msg.msg_flags = 0;
            iov.iov_base  = buf;
            iov.iov_len   = sizeof(buf);
            ret = kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0);
            if (ret > 0)
                parse_response(buf);
        }

        sock_release(sock);

    sleep:
        msleep_interruptible(UPDATE_INTERVAL);
    }
    return 0;
}

static ssize_t moex_read(struct file *file, char __user *buf,
                         size_t count, loff_t *ppos)
{
    ssize_t ret;
    spin_lock(&data_lock);
    ret = simple_read_from_buffer(buf, count, ppos, stock_data,
                                  strlen(stock_data));
    spin_unlock(&data_lock);
    return ret;
}

static const struct proc_ops proc_fops = {
    .proc_open  = simple_open,
    .proc_read  = moex_read,
};

static int __init moex_init(void)
{
    stock_data = kmalloc(256, GFP_KERNEL);
    if (!stock_data)
        return -ENOMEM;
    strcpy(stock_data, "No data");

    proc_create("moex_stocks", 0444, NULL, &proc_fops);

    update_thread = kthread_run(update_worker, NULL, "moex_updater");
    if (IS_ERR(update_thread)) {
        proc_remove(proc_mkdir("moex_stocks", NULL));
        kfree(stock_data);
        return PTR_ERR(update_thread);
    }

    printk(KERN_INFO "moex: module loaded\n");
    return 0;
}

static void __exit moex_exit(void)
{
    kthread_stop(update_thread);
    remove_proc_entry("moex_stocks", NULL);
    kfree(stock_data);
    printk(KERN_INFO "moex: module unloaded\n");
}

module_init(moex_init);
module_exit(moex_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ваше Имя");
MODULE_DESCRIPTION("Просмотр котировок MOEX через /proc/moex_stocks");
