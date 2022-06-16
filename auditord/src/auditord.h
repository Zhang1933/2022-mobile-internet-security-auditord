#ifndef _AUDITORD_H_
#define _AUDITORD_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/wireless.h>
#include <linux/netlink.h>
#include <time.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>
//#include <uci.h>
#include <sys/statfs.h>
#include <dirent.h>
#include <stdarg.h>
//#include <libubox/uloop.h>
//#include <libubox/list.h>
#include <pthread.h>
#include <syslog.h>
#include <sys/statfs.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <netdb.h>
#include <netinet/tcp.h>


#if 0
#define DEBUG  //printf
#else
#define DEBUG(format,arg...)  \
do {                          \
    if(debug_enable){   \
        printf("FILE : %s , LINE : %d "format,__FILE__,__LINE__,##arg);  \
    } \
}while(0)
#endif

// 用来调试锁的打印
#if 0
#define MUTEX_DEBUG  printf
#else
#define MUTEX_DEBUG(format, args...)
#endif


#define ADT_VERSION         "V1.0"

#define AC_AUDITORD_CONFIG_FILE     "/etc/config/audit"
#define AUDITORD_PID_FILE                     "/var/run/audit.pid"

#define MAC_FMT_STR                                 "%02x%02x%02x%02x%02x%02x"

// 通过这条命令，可以获取路由周边的guest ssid对于的mac和ssid名
#define AUT_SCAN_WIFI_CMD                   "iwinfo wlan0 scan | awk '{if(match($0,\"Address:\") || match($0,\"ESSID:\")){ print substr($0,RSTART+RLENGTH)}}' | xargs -n2"

// x86平台支持，判断平台的定义
//#if !defined( PC_TARGET_LINUX_X86 ) && !defined( PC_TARGET_LINUX_RALINK ) && !defined( PC_TARGET_LINUX_ATHEROS )
//#error "You must should define one platform x86 or ralink or atheros !"
//#endif

#ifndef ADT_SUCCESS
#define ADT_SUCCESS 0
#endif

#ifndef ADT_FALSE
#define ADT_FALSE -1
#endif

#define NETLINK_AUDITOR_PROTO       26      /* netlink protocal for collecting auditor info */

#define MAC_LEN_IN_BYTE             6

// 定义审计消息最大长度
#define AUDITOR_INFO_MAX_LEN        2048
#define AUDITOR_MSG_MAX_LEN         1024
#define MAXLINE                     1024

#define AUDITOR_MAX_IP_SIZE         32

#define TELNET_LOGIN_LEN            32
#define TELNET_PASSWD_LEN           32
#define TELNET_CMD_LINE_LEN         256

#define FTP_LOGIN_LEN               32
#define FTP_PASSWD_LEN              128
#define FTP_CMD_LINE_LEN            512

#define SSID_NAME_MAX_LEN           512

// 两个平台的USR信号不同
/* 用户在网上上修改配置文件提交应用后，发送信号给函数去更新读取新的配置信息 */
#ifdef PC_TARGET_LINUX_RALINK
#define SIG_AC_READ_AUDITORD_CONF   17
#else
#define SIG_AC_READ_AUDITORD_CONF   12
#endif


#define AUDIT_HISTORY_LIST_EXPIRED           300     /* 定义历史记录的超时时间为5分钟 */

// 定义审计的历史记录清除的时间间隔(60秒)
#define AUDIT_CLEAN_EXPIRE_LIST_INTERVAL     60

// 定义审计的统计周边ssid的时间间隔(600秒)
#define AUDIT_SCAN_GUEST_SSID_INTERVAL       600


// 如果这个wifi guest信息，在3次循环中都没更新，
// 则认为不存在了，删掉
#define AUDIT_GUEST_SSID_LIST_EXPIRED        (3*AUDIT_SCAN_GUEST_SSID_INTERVAL)


// add by xiejian 20150709 , 判断是否为空字符
#define IS_SPACE(c)  ((c) == ' ' || (c) == '\t' || (c) == '\n' )


#ifndef SIZE_ARRAY
#define SIZE_ARRAY(a)                (sizeof(a) / sizeof((a)[0]))
#endif


/* 得到数组元素在数组中的便宜量 */
#ifndef offsetof
#define offsetof(TYPE, MEMBER)       ((size_t) &((TYPE *)0)->MEMBER)
#endif


#define PRINT_MAC(mac)  \
    do { \
        DEBUG( "0x%02x:%02x:%02x:%02x:%02x:%02x\n", \
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]); \
    } while(0)



/*convert a string,which length is 18, to a macaddress data type.*/
#define COPY_STR2MAC(mac,str)  \
    do { \
        int i = 0; \
        for(i = 0; i < MAC_LEN_IN_BYTE; i++) {\
            mac[i] = (a2x(str[i*3]) << 4) + a2x(str[i*3 + 1]);\
        }\
    } while(0)



// 定义审计的锁，这样定义主要是方便以后调试，要是出现死锁情况，打开宏可以很方便调试
#define AUDIT_METUX_LOCK(mutex) \
    do { \
        MUTEX_DEBUG("FUNC : %s LINE : %d lock %s\n",__func__,__LINE__,#mutex); \
        pthread_mutex_lock(&mutex); \
        }while(0)


#define AUDIT_METUX_UNLOCK(mutex) \
    do { \
        MUTEX_DEBUG("FUNC : %s LINE : %d unlock %s\n",__func__,__LINE__,#mutex); \
        pthread_mutex_unlock(&mutex); \
        }while(0)



/* 定义用来检测审计的开关是否打开，如果没有打开则直接退出 */
#define CHECK_AUDIT_STATE_OR_EXIT( )  \
   do {                                  \
      if( !get_audit_switch() ){                               \
         DEBUG("FUNC : %s LINE : %d Please open audit Switch!\n",__func__,__LINE__); \
         return -1 ; \
      } \
   }while(0)



// modify by xiejian 20150625 , 增加对从服务器获取的配置参数的值的判断，如果为空值则不进行
// 修改
#define AUDIT_CHANGE_CONFIG(x,y) \
    do {  \
        if( y[0] != 0 ) \
        { \
            if(0 != audit_change_config_value("audit","audit",x,y)) \
                goto exit; \
        } \
    }while(0)


typedef enum tag_auditor_info_type {
    ENUM_AUDITOR_TYPE_URL = 1, /*GET*/
    ENUM_AUDITOR_TYPE_ID,
    ENUM_AUDITOR_TYPE_TELNET,
    ENUM_AUDITOR_TYPE_FTP,
    ENUM_AUDITOR_TYPE_SMTP,
    ENUM_AUDITOR_TYPE_POP3,
    ENUM_AUDITOR_TYPE_IMAP,
    ENUM_AUDITOR_TYPE_FORUM,
    ENUM_AUDITOR_TYPE_WEIBO,
    ENUM_AUDITOR_TYPE_SEARCH,
    ENUM_AUDITOR_TYPE_WEBMAIL,
    ENUM_AUDITOR_TYPE_URL_POST,
    ENUM_AUDITOR_TYPE_CHAT,
    ENUM_AUDITOR_TYPE_USER_LEAVE,
    ENUM_AUDITOR_TYPE_REGISTER_INFO
} auditor_type_t;


typedef struct tag_auditor_telnet_list {
    struct tag_auditor_telnet_list  *pre;
    struct tag_auditor_telnet_list  *next;

    unsigned char   src_mac[MAC_LEN_IN_BYTE + 2];
    unsigned long   src_ip;
    unsigned long   dst_ip;
    int             src_port;
    int             dst_port;
    char            login[TELNET_LOGIN_LEN];
    char            passwd[TELNET_PASSWD_LEN];
    char            cmd[TELNET_CMD_LINE_LEN];
    unsigned long   first_time;
    unsigned long   last_time;
} telnet_node_t, telnet_list_t;


typedef struct tag_auditor_ftp_list {
    struct tag_auditor_ftp_list     *pre;
    struct tag_auditor_ftp_list     *next;

    unsigned char   src_mac[MAC_LEN_IN_BYTE + 2];
    unsigned long   src_ip;
    unsigned long   dst_ip;
    int             src_port;
    int             dst_port;
    char            username[FTP_LOGIN_LEN];
    char            password[FTP_PASSWD_LEN];
    char            cmd[FTP_CMD_LINE_LEN];
    unsigned long   first_time;
    unsigned long   last_time;
} ftp_node_t, ftp_list_t;


typedef struct tag_auditor_ssid_list {
    struct tag_auditor_ssid_list     *pre;
    struct tag_auditor_ssid_list     *next;

    unsigned int    has_send;         // 标识是否已经发送了
    unsigned char   ssid_mac[MAC_LEN_IN_BYTE + 2];
    char            ssid[SSID_NAME_MAX_LEN];
    unsigned long   last_time;

} ssid_node_t, ssid_list_t;


typedef struct tag_netlink_telnet_info {
    unsigned char   src_mac[MAC_LEN_IN_BYTE + 2];
    unsigned long   src_ip;
    unsigned long   dst_ip;
    int             src_port;
    int             dst_port;
    char            login[TELNET_LOGIN_LEN];
    char            passwd[TELNET_PASSWD_LEN];
    char            cmd[TELNET_CMD_LINE_LEN];

} telnet_info_t;

typedef struct tag_netlink_ftp_info {
    unsigned char   src_mac[MAC_LEN_IN_BYTE + 2];
    unsigned long   src_ip;
    unsigned long   dst_ip;
    int             src_port;
    int             dst_port;
    char            username[FTP_LOGIN_LEN];
    char            password[FTP_PASSWD_LEN];
    char            cmd[FTP_CMD_LINE_LEN];
} ftp_info_t;


typedef struct tag_netlink_auditor_info {
    int             info_type;
    char            info[AUDITOR_INFO_MAX_LEN - 4];
} auditor_info_t;

/***********************************************************************************/
// 下面这些都是发送给服务端的结构体消息
typedef struct tag_auditor_telnet_msg {
    char            login[TELNET_LOGIN_LEN];
    char            passwd[TELNET_PASSWD_LEN];
    char            cmd[TELNET_CMD_LINE_LEN];
} telnet_msg_t;


typedef struct tag_auditor_ftp_msg {
    char            username[FTP_LOGIN_LEN];
    char            password[FTP_PASSWD_LEN];
    char            cmd[FTP_CMD_LINE_LEN];
} ftp_msg_t;


typedef struct tag_auditor_ssid_msg {
    unsigned char   ssid_mac[MAC_LEN_IN_BYTE + 2];
    char            ssid[SSID_NAME_MAX_LEN];
} ssid_msg_t;

// 发送个服务端的消息
typedef struct tag_auditor_udp_msg {
    char            info[AUDITOR_MSG_MAX_LEN - 4];
    uint8_t         info_type;
} auditor_msg_t;


typedef enum tag_auditor_msg_type {
    AUDITOR_MSG_TYPE_TELNET = 1,
    AUDITOR_MSG_TYPE_FTP,
    AUDITOR_MSG_TYPE_SSID
} msg_type_t;

/***********************************************************************************/


// 定义发送消息的接口

typedef int (*audit_send_message_handler)(int fd, struct sockaddr_in *p_addr);

// 定义审计回调事件的接口
typedef int (*audit_event_handler)( void );

// 定义审计超时处理时间的接口
typedef void (*audit_clear_expire_list_handler)( void );



/* Async event queue */
/* 定义审计的事情类型，用于发送不同的消息 */
typedef struct _audit_event_desc_s_ {
    bool                has_event;                             //标示是否有事件
    audit_event_handler  cb;                                    //定义审计回调事件的接口
    pthread_mutex_t     mutex;                                 //互斥锁，信号处理函数与主函数访问共享变量
    char                msg[0];                                //定义事件的消息，暂时保留，没有用到
} audit_event_desc_s;



#endif
