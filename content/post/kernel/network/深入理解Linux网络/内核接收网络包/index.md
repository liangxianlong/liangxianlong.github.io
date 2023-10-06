---
title: '内核接收网络包'
date: 2023-09-27T10:37:25+08:00
categories:
    - kernel-network
tags:
    - 
---

通常来说如下代码在网络通信中用于接收对端的数据:

```c
int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    connect(sock, ...);
    read(sock, buffer, sizeof(buffer) - 1);
    ...
}
```

上述流程从用户态的角度来说比较简单，但是其背后涉及到了内核、网卡驱动等一列复杂的处理流程。本文以`linux-5.10.194`以及`ixgbe`网卡来阐述此流程。

## Linux网络收包概述

以`Linux`的视角看`TCP/IP`的网络分层模型如下图所示：

<div align=center><img src ="tcp_ip分层模型.png"/></div>

`Linux`内核主要实现传输层和网络层，网卡驱动实现链路层。当网卡设备上有数据到达时，会给`CPU`的相关引脚触发一个电压变化，以通知`CPU`来处理数据；此种方式被称为中断。中断分为上半部和下半部：

- 上半部：只进行最简单的动作，快速处理然后释放`CPU`。

- 下半部：中断中剩下的大部分工作都由下半部继续处理。

`Linux`对于中断下半部的实现方式是软中断，由`ksoftirqd`内核线程全权处理。硬中断是通过给`CPU`物理引脚施加电压变化实现的，而软中断是通过给内存中的一个变量赋予二进制值以标记有软中断发生。

如下图总结了内核收包的路径图：

<img src="recv_packet.png" title="" alt="" data-align="center">

流程如下：

1. 数据帧从外部网络到达网卡。

2. 网卡收到数据，以`DMA`的方式把网卡收到的数据帧写到内存里。

3. 网卡向`CPU`发起一个中断，以通知`CPU`有数据到达。

4. `CPU`收到中断请求，调用网卡驱动注册的中断处理函数简单处理然后发出软中断，并快速释放`CPU`。

5. `ksoftirqd`内核线程检测到有软中断请求到达，调用`poll`开始轮询收包，最后交由各级协议栈处理。

## 网络子系统初始化

在真正能处理外部数据帧之前，内核协议栈、网卡驱动需要做很多的准备工作。

### 创建ksoftirqd内核线程

`Linux`内核中的软中断都是在内核线程`ksoftirqd`中进行的。系统上`ksoftirqd`线程的数等于`CPU`的数量(可以使用`ps -ef | grep ksoftirqd`查看)。

在`Linux`系统初始化的时候调用`early_initcall(spawn_ksoftirqd)`来创建`ksoftirqd`内核线程。关于`early_initcall`的机制请参考[Linux的initcall机制](https://zhuanlan.zhihu.com/p/627521955)，此处不做详细说明。`spawn_ksoftirqd`函数流程如下:

```c
static __init int spawn_ksoftirqd(void)
{
    cpuhp_setup_state_nocalls(CPUHP_SOFTIRQ_DEAD, "softirq:dead", NULL,
                  takeover_tasklets);
    BUG_ON(smpboot_register_percpu_thread(&softirq_threads));

    return 0;
}
early_initcall(spawn_ksoftirqd);
```

可以看到`spawn_ksoftirqd`将`softirq_threads`结构体以地址的形式传入`smpboot_register_percpu_thread`。如下所示为相关的代码：

```c
static struct smp_hotplug_thread softirq_threads = {
    .store            = &ksoftirqd,
    .thread_should_run    = ksoftirqd_should_run,
    .thread_fn        = run_ksoftirqd,
    .thread_comm        = "ksoftirqd/%u",
};
```

```c
/**
 * smpboot_register_percpu_thread - Register a per_cpu thread related
 *                         to hotplug
 * @plug_thread:    Hotplug thread descriptor
 *
 * Creates and starts the threads on all online cpus.
 */
int smpboot_register_percpu_thread(struct smp_hotplug_thread *plug_thread)
{
    unsigned int cpu;
    int ret = 0;

    get_online_cpus();
    mutex_lock(&smpboot_threads_lock);
    for_each_online_cpu(cpu) {
        ret = __smpboot_create_thread(plug_thread, cpu);
        if (ret) {
            smpboot_destroy_threads(plug_thread);
            goto out;
        }
        smpboot_unpark_thread(plug_thread, cpu);
    }
    list_add(&plug_thread->list, &hotplug_threads);
out:
    mutex_unlock(&smpboot_threads_lock);
    put_online_cpus();
    return ret;
}
EXPORT_SYMBOL_GPL(smpboot_register_percpu_thread);
```

可以看到`smpboot_register_percpu_thread`会为每个`online CPU`创建对应的`ksoftirqd`内核线程，进入线程循环函数`ksoftirqd_should_run`和`run_ksoftirqd`。需要注意的是软中断不仅有网络软中断，还包括其他类型，参考如下：

```c
enum
{
    HI_SOFTIRQ=0,
    TIMER_SOFTIRQ,
    NET_TX_SOFTIRQ,
    NET_RX_SOFTIRQ,
    BLOCK_SOFTIRQ,
    IRQ_POLL_SOFTIRQ,
    TASKLET_SOFTIRQ,
    SCHED_SOFTIRQ,
    HRTIMER_SOFTIRQ,
    RCU_SOFTIRQ,    /* Preferable RCU should always be the last softirq */

    NR_SOFTIRQS
};
```

### 网络子系统初始化

在网络子系统的初始化过程中，会为每个`CPU`初始化`softnet_data`，也会为`NET_RX_SOFTIRQ`和`NET_RX_SOFTIRQ`注册处理函数，流程如下图所示：

<img title="" src="net_dev_init.png" alt="" data-align="center" width="1844">

从上图可知网络子系统的初始化由`net_dev_init`函数完成，该函数主要完成:

- 为每一个`CPU`申请一个`softnet_data`数据结构，这个数据结构里的`poll_list`用于等待驱动程序将其`poll`函数注册进来。

- 通过`open_softirq`为`NET_RX_SOFTIRQ`以及`NET_RX_SOFTIRQ`分别注册处理函数`net_rx_action`和`net_tx_action`。

如下所示为相关代码：

```c
static int __init net_dev_init(void)
{
    ...
    for_each_possible_cpu(i) {
        struct work_struct *flush = per_cpu_ptr(&flush_works, i);
        // 为当前cpu创建softnet_data数据
        struct softnet_data *sd = &per_cpu(softnet_data, i);

        INIT_WORK(flush, flush_backlog);

        skb_queue_head_init(&sd->input_pkt_queue);
        skb_queue_head_init(&sd->process_queue);
#ifdef CONFIG_XFRM_OFFLOAD
        skb_queue_head_init(&sd->xfrm_backlog);
#endif
        // 注册poll_list
        INIT_LIST_HEAD(&sd->poll_list);
        sd->output_queue_tailp = &sd->output_queue;
#ifdef CONFIG_RPS
        sd->csd.func = rps_trigger_softirq;
        sd->csd.info = sd;
        sd->cpu = i;
#endif

        init_gro_hash(&sd->backlog);
        sd->backlog.poll = process_backlog;
        sd->backlog.weight = weight_p;
    }
    ...
    // 注册net_tx_action
    open_softirq(NET_TX_SOFTIRQ, net_tx_action);
    // 注册net_rx_action
    open_softirq(NET_RX_SOFTIRQ, net_rx_action);
    ...
    return rc;
}
subsys_initcall(net_dev_init);
```

通过`open_softirq`可以发现，软中断处理函数最终记录在`softirq_vec`变量里，后面`ksoftirqd`线程收到软中断的时候，也会使用`softirq_vec`变量来找到每一种软中断所对应的处理函数：

```c
void open_softirq(int nr, void (*action)(struct softirq_action *))
{
    softirq_vec[nr].action = action;
}
```

`softirq_vec`变量定义如下:

```c
static struct softirq_action softirq_vec[NR_SOFTIRQS] __cacheline_aligned_in_smp;
```

可以看到`softirq_vec`其实就是结构体`struct softirq_action`组成的数组。一个`struct softirq_action`表示某一类型的软中断处理函数：

```c
struct softirq_action
{
    void    (*action)(struct softirq_action *);
};
```

### 协议栈注册

内核实现了网络层的`IP`协议，也实现了传输层的`TCP`协议和`UDP`协议。内核通过`fs_initcall`
