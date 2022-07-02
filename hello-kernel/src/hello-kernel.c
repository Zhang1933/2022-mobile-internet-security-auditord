/*
 * telnet不保证"Character mode"下能用!!
*/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netlink.h>
#include <net/netlink.h>
#include <net/net_namespace.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("1933");
MODULE_DESCRIPTION("An net sniff module for demonstration");
MODULE_VERSION("1.0");

#define NETLINK_AUDITOR_PROTO       26 // 自定义协议 

#define MAC_LEN_IN_BYTE             6
#define FTP_LOGIN_LEN               32
#define FTP_PASSWD_LEN              128
// 一次只存储一个命令
#define FTP_CMD_LINE_LEN            32

#define TELNET_LOGIN_LEN            32
#define TELNET_PASSWD_LEN           32
#define TELNET_CMD_LINE_LEN         128

//一共payload长度
#define AUDITOR_INFO_MAX_LEN        228

#define DEBUG(format,arg...)  \
    printk("LINE : %d " format,__LINE__,##arg);


static char FTPUsername[FTP_LOGIN_LEN]={'\0'};
static char FTPPassword[FTP_PASSWD_LEN]={'\0'};
static unsigned short src_ftp_port=0;  // 原端口是进程号,根据进程号可以向用户空间中的程序发包
static unsigned int src_ftp_ip=0;

static char TelnetUsername[TELNET_LOGIN_LEN]={'\0'};
static char TelnetPassword[TELNET_PASSWD_LEN]={'\0'};
static unsigned short src_telnet_port;
static unsigned int src_telnet_ip;

#define MAX_FTPCMDSET 6
static const unsigned short FTP_MATCH_CMD_LEN=4;
// 如果长度不够，填成4位
static const char *FTP_CMD_SET[MAX_FTPCMDSET]={
    "USER","PASS","QUIT","LIST","CWD\x20","PWD\x0d"
};


// 记录审计程序的端口号
static int  auditord_pid=0;
static struct sock *sk; //内核端socket

// 与用户空间的程序接口对应上
typedef struct tag_netlink_ftp_info {
    unsigned char   src_mac[MAC_LEN_IN_BYTE + 2];
    unsigned long   src_ip;
    unsigned long   dst_ip;
    int             src_port;
    int             dst_port;
    char            username[FTP_LOGIN_LEN];
    char            password[FTP_PASSWD_LEN];
    char            cmd[FTP_CMD_LINE_LEN];
} ftp_info_t; //224 字节
 
typedef struct tag_netlink_auditor_info {
    int             info_type;
    char            info[AUDITOR_INFO_MAX_LEN-4];
} auditor_info_t;// netlink返回数据

typedef struct tag_netlink_telnet_info {
    unsigned char   src_mac[MAC_LEN_IN_BYTE + 2];
    unsigned long   src_ip;
    unsigned long   dst_ip;
    int             src_port;
    int             dst_port;
    char            login[TELNET_LOGIN_LEN];
    char            passwd[TELNET_PASSWD_LEN];
    char            cmd[TELNET_CMD_LINE_LEN];
} telnet_info_t; // 224字节


/* Used to describe our Netfilter hooks */
static struct nf_hook_ops post_hook;

/* dump packet's data */
void pkt_hex_dump(struct sk_buff *skb){
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch; 
    struct iphdr *ip = (struct iphdr *)skb_network_header(skb);

    DEBUG("%s:Packet hex dump:\n",__func__);
    data = (uint8_t *) skb_network_header(skb);

    len=ntohs(ip->tot_len);

    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        printk("%06d\t", li);
        linelen = min(remaining, rowsize);
        remaining -= rowsize;
        for (l = 0; l < linelen; l++) {
            ch = data[l];
            printk(KERN_CONT "%02X ", (uint32_t) ch);
        }
        data += linelen;
        li += 10; 

        printk(KERN_CONT "\n");
    }
}

/*得到data字段长度.
 * 传入data部分长度，以及是否是ftp数据包
 */
static unsigned short Get_Total_Data_Len(const unsigned char *data,int if_ftp){
    int i=0;
    if(if_ftp){
        for(;i<FTP_CMD_LINE_LEN;i++){
            if(data[i]=='\x0d'||data[i]=='\0'){
                return i;    
            }
        }
    } 
    else{
        // Telnet
        for(;i<TELNET_CMD_LINE_LEN;i++){
            // 是0a表示回车符
            if(data[i]=='\x0a'||data[i]=='\0'||data[i]>(unsigned char)'\x7e'){
                return i;    
            }
        }
    }
    return i;
}

/*
 * 向用户程序通讯,发数据,可能以后会扩充发包范围,pos在telnet是填0
 */
static void Send_Content(struct iphdr *ip,struct tcphdr *tcp,const unsigned char *data,int pos,int data_len,char if_ftp){
    struct nlmsghdr *out_nlh=NULL;
    void *out_payload;
    auditor_info_t auditor;
    struct sk_buff *out_skb;

    if(auditord_pid==0){
            return;
    }
    if(if_ftp){
        // quit 命令重置所保留的信息
        ftp_info_t ftp;
        int temp=min(data_len,FTP_CMD_LINE_LEN-1);

        strcpy(ftp.src_mac,"aaaa"); //mac地址不用填其实
        ftp.src_ip=src_ftp_ip;
        ftp.dst_ip=ntohl(ip->daddr);
        ftp.src_port=src_ftp_port;
        strcpy(ftp.username,FTPUsername);
        strcpy(ftp.password,FTPPassword);
        strncpy(ftp.cmd,data,temp);
        ftp.cmd[temp]='\0';

        printk("\n");
        DEBUG("[%s:Send ftp data]src port:%hu, src ip:%lx ,FtpUsername:%s ,FtpPassword:%s,FtpCMd:%s\n\n",__func__,ftp.src_port,ftp.src_ip,ftp.username,ftp.password,ftp.cmd);

        //开始向用户程序发包
        auditor.info_type=4; // type 4 ftp 
        memcpy(auditor.info,&ftp,sizeof(ftp_info_t));
    }
    else{
        telnet_info_t tel;
        int temp=min(data_len,TELNET_CMD_LINE_LEN-1);

        strcpy(tel.src_mac,"aaaa"); //mac地址不用填其实
        tel.src_ip=src_telnet_ip;
        tel.dst_ip=ntohl(ip->daddr);
        tel.src_port=src_telnet_port;
        strcpy(tel.login,TelnetUsername);
        strcpy(tel.passwd,TelnetPassword);
        strncpy(tel.cmd,data,temp);
        tel.cmd[temp]='\0';

        printk("\n");
        DEBUG("[%s:Send TELNET data]src port:%hu, src ip:%x ,TelnetUsername:%s ,TelnetPassword:%s,TelnetCMd:%s\n",__func__,src_telnet_port,src_telnet_ip,TelnetUsername,TelnetPassword,tel.cmd);
    
        //开始向用户程序发包
        auditor.info_type=3; // type 3 telnet 
        memcpy(auditor.info,&tel,sizeof(telnet_info_t));
    }
    out_skb = nlmsg_new(AUDITOR_INFO_MAX_LEN, GFP_KERNEL); 
    if (!out_skb){
        DEBUG("[%s] out_skb allocate failure\n",__func__);
        goto failure;
    }
    out_nlh = nlmsg_put(out_skb,0,0,0,AUDITOR_INFO_MAX_LEN, 0); //填充协议头数据 
    if(!out_nlh){
        DEBUG("[%s]:insufficient to store the message header and payload.\n",__func__);
        goto failure;
    }
    out_payload = nlmsg_data(out_nlh);
    memcpy(out_payload,&auditor,sizeof(auditor));
    if(nlmsg_unicast(sk, out_skb,auditord_pid)<0){
        DEBUG("[%s]: send netlink packet failed!\n", __func__);
    }
    DEBUG("[%s]: send netlink packet success!\n", __func__);
    return;

failure:
    DEBUG("[%s] failed in \n",__func__);
    return; 
}

/*
 * 提取FTP数据包中的数据
 */
static void Get_FTP_Data(struct sk_buff *skb,int pos){
    struct iphdr *ip =(struct iphdr *)skb_network_header(skb);
    struct tcphdr* tcp =(struct tcphdr *)skb_transport_header(skb);
    const  unsigned char* data = (unsigned char *)((unsigned char *)tcp + (tcp->doff * 4));
    int data_len=(unsigned short)ntohs(ip->tot_len) - (unsigned short)(ip->ihl<<2) - (unsigned short)(tcp->doff<<2); 

    if(data_len<=0)return;

    switch(pos){
        case 0:{
            // 说明是USER命令,提取USERNAME字段,无脑更新username. ,直接复制后面整个
            int temp=min(data_len-5,FTP_LOGIN_LEN-1);
            strncpy(FTPUsername,data+5,temp);
            FTPUsername[temp]='\0';
            src_ftp_ip=ntohl(ip->saddr);
            src_ftp_port=ntohs(tcp->source);
            break;
        }
        case 1:{
            //说明是PASSWORD命令,在源端口相同的情况下，更新password
            if(src_ftp_ip==ntohl(ip->saddr)&&src_ftp_port==ntohs(tcp->source)){
                int temp=min(data_len-5,FTP_PASSWD_LEN-1);
                strncpy(FTPPassword,data+5,temp);
                FTPPassword[temp]='\0';
            }
            break;
        }
        default:{
            DEBUG("%s TFP match pos : %d\n",__func__,pos);
            // 说明匹配到的是命令,准备向用户程序发包
            Send_Content(ip,tcp,data,pos,data_len,1);
        }
    }
}

/* This is the hook function itself */
unsigned int watch_out(void *priv,struct sk_buff *skb,const struct nf_hook_state *state){
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    unsigned char *data=NULL;

    ip = (struct iphdr *)skb_network_header(skb);
    if (ip->protocol != IPPROTO_TCP){
        return NF_ACCEPT;
    }

    tcp = (struct tcphdr *)skb_transport_header(skb);
    data = (unsigned char *)((unsigned char *)tcp + (tcp->doff * 4));
    
    unsigned short tcp_payload_len=(unsigned short)ntohs(ip->tot_len) - (unsigned short)(ip->ihl<<2) - (unsigned short)(tcp->doff<<2); 
    /* Now check to see if it's an FTP packet */
    if (tcp->dest == htons(21)){
        int pos=0;
        unsigned short temp_len=min(tcp_payload_len,FTP_MATCH_CMD_LEN);
        if(temp_len==0)return NF_ACCEPT;
        // 说明可能是ftp包
        //pkt_hex_dump(skb);
        for(;pos<MAX_FTPCMDSET;pos++){
            if(strncmp(FTP_CMD_SET[pos],data,temp_len)==0){
                break;
            }
        }
        if(pos==MAX_FTPCMDSET){
            return NF_ACCEPT;
        }
        else{
            //说明匹配到FTP命令
            Get_FTP_Data(skb,pos);
        }
    }
    else if(tcp->dest==htons(23)){
        DEBUG("[%s]:Data Len:%hu\n",__func__,tcp_payload_len);
//        pkt_hex_dump(skb);
        if(data[0]<(unsigned char)'\x7e'&&tcp_payload_len>0){
            // 没有可打印字符范围,记录用户名
            if(TelnetUsername[0]=='\0'){
                unsigned short temp=min(tcp_payload_len,(unsigned short)(TELNET_LOGIN_LEN-1));
                strncpy(TelnetUsername,data,temp); 
                TelnetUsername[temp]='\0';
                src_telnet_ip=ntohl(ip->saddr);
                src_telnet_port=ntohs(tcp->source);
                DEBUG("Set Telnet UserName:%s\n",TelnetUsername);
                TelnetPassword[0]='\0';
                return NF_ACCEPT;
            }
            if(TelnetPassword[0]=='\0'){
                // 记录密码
                if(src_telnet_ip==ntohl(ip->saddr)&&src_telnet_port==ntohs(tcp->source)){
                    unsigned short temp=min(tcp_payload_len,(unsigned short)(TELNET_PASSWD_LEN-1));
                    strncpy(TelnetPassword,data,temp); 
                    TelnetPassword[temp]='\0';
                    DEBUG("[%s] Set Telnet pass:%s\n",__func__,TelnetPassword);
                }
                else{
                    // 否则的话是新会话,更新用户
                    unsigned short temp=min(tcp_payload_len,(unsigned short)(TELNET_LOGIN_LEN-1));
                    strncpy(TelnetUsername,data,temp); 
                    TelnetUsername[temp]='\0';
                    src_telnet_ip=ntohl(ip->saddr);
                    src_telnet_port=ntohs(tcp->source);
                    TelnetPassword[0]='\0';
                    DEBUG("[%s] Renew Telnet UserName:%s\n",__func__,TelnetUsername);
                }
                return NF_ACCEPT;
            }
            if(src_telnet_ip==ntohl(ip->saddr)&&src_telnet_port==ntohs(tcp->source)){
                //得到指令,准备发包
                Send_Content(ip,tcp,data,0,tcp_payload_len,0);
            }
            else{
                //新会话,更新用户名
                unsigned short temp=min(tcp_payload_len,(unsigned short)(TELNET_LOGIN_LEN-1));
                strncpy(TelnetUsername,data,temp); 
                TelnetUsername[temp]='\0';
                src_telnet_ip=ntohl(ip->saddr);
                src_telnet_port=ntohs(tcp->source);
                TelnetPassword[0]='\0';
                DEBUG("[%s] Renew Telnet UserName:%s\n",__func__,TelnetUsername);
            }
        }
    }
    //    pkt_hex_dump(skb);
    //    printk("hex : data[0-3] = 0x%02x%02x%02x%02x\n", data[0], data[1], data[2], data[3]);
    //    printk("char: data[0-3] = %c%c%c%c\n", data[0], data[1], data[2], data[3]);
    //    printk("--------------- findpkt_iwant ------------------\n");
    return NF_ACCEPT;
}

//接收消息回调函数
static void nl_get_status_ready(struct sk_buff *skb){
    struct nlmsghdr *nlh = (struct nlmsghdr *) skb->data;
    auditord_pid=nlh->nlmsg_pid;
    DEBUG("[%s]:Get auditor pid:%d\n",__func__,auditord_pid);
}

/* Initialisation routine */
static int __init hello_kernel_init(void){
    /* Fill in our hook structure */
    post_hook.hook = watch_out;         /* Handler function */
    post_hook.hooknum  = NF_INET_POST_ROUTING; 
    post_hook.pf       = AF_INET;
    post_hook.priority = NF_IP_PRI_FIRST;   /* Make our function first */

    nf_register_net_hook(&init_net,&post_hook);
    struct netlink_kernel_cfg nlcfg = {
        .input = nl_get_status_ready,
    };
    sk = netlink_kernel_create(&init_net,NETLINK_AUDITOR_PROTO, &nlcfg);
    if (!sk){
        DEBUG("[%s]:Netlink create error!\n",__func__);
    }
    DEBUG("[%s]:Initialed ok!\n",__func__);
    return 0;
}

/* Cleanup routine */
static void __exit hello_kernel_exit(void){

    netlink_kernel_release(sk);
    nf_unregister_net_hook(&init_net,&post_hook);
    DEBUG("[%s]:Existing Finish\n",__func__);
}

// 登记初始化函数及清理函数
module_init(hello_kernel_init);
module_exit(hello_kernel_exit);
