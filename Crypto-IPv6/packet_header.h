#ifndef PACKET_HEADER_H
#define PACKET_HEADER_H

#ifndef u_char
#define u_char unsigned char
#endif

#ifndef u_int8
#define u_int8 unsigned char
#endif

#ifndef u_int16
#define u_int16 unsigned short
#endif

#ifndef u_int32
#define u_int32 unsigned int
#endif

#ifndef u_int64
#define u_int64 unsigned long long
#endif

#ifndef u_short
#define u_short unsigned short
#endif

/* 以太帧头 */
typedef struct tagEthHeader_t
{
    //Pcap捕获的数据帧头
    u_int8 dest_hwaddr[6];   //目的MAC地址
    u_int8 source_hwaddr[6]; //源MAC地址
    u_short frame_type;      //帧类型
}EthHeader_t;

//IP数据报头
typedef struct tagIPHeader_t
{
    //IP数据报头
    u_int8  Ver_HLen; //版本+报头长度
    u_int8  TOS;      //服务类型
    u_int16 TotalLen;//总长度
    u_int16 ID;      //标识
    u_int16 Flag_Segment; //标志+片偏移
    u_int8  TTL;      //生存周期
    u_int8  Protocol; //协议类型
    u_int16 Checksum;//头部校验和
    u_int8 SrcIP[4];   //源IP地址
    u_int8 DstIP[4];   //目的IP地址
} IPHeader_t;

//IPv6基本首部
#if 0
typedef struct tagIPv6Header_t
{
    u_char    version:4;      // 4-bit版本号
    u_char  traffic_class:8;  // 8-bit流量等级
    u_int32 label:20;       // 20-bit流标签
    u_short    payload_len;    // 16-bit 载荷长度
    u_char    next_header;    // 8-bit 下一首部
    u_char    hop_limit;        // 8-bit 跳数限制
    struct
    {
        u_int64 prefix_subnetid;
        u_char interface_id[8];
    } src_ip;                // 128-bit 源地址
    struct
    {
        u_int64 prefix_subnetid;
        u_char interface_id[8];
    } dst_ip;                // 128-bit 目的地址

} IPv6Header_t;

typedef struct in6_addr {
  union {
    u_char  Byte[16];
    u_short Word[8];
  } u;
} IN6_ADDR, *PIN6_ADDR, FAR *LPIN6_ADDR;

#endif


typedef struct tagIPv6Header_t
{
//     union
//     {
//         struct ip6_hdrctl
//         {
//             u_int32_t ip6_unl_flow;/* 4位的版本，8位的传输与分类，20位的流标识符 */
//             u_int16_t ip6_unl_plen;/* 报头长度 */
//             u_int8_t ip6_unl_nxt;  /* 下一个报头 */
//             u_int8_t ip6_unl_hlim; /* 跨度限制 */
//         }ip6_unl ;

//         u_int8_t ip6_un2_vfc;/* 4位的版本号，跨度为4位的传输分类 */
//     }ip6_ctlun ;

// #define ip6_vfc              ip6_ctlun.ip6_un2_vfc
// #define ip6_flow             ip6_ctlun.ip6_unl.ip6_unl_flow
// #define ip6_plen             ip6_ctlun.ip6_unl.ip6_unl_plen
// #define ip6_nxt              ip6_ctlun.ip6_unl.ip6_unl_nxt
// #define ip6_hlim             ip6_ctlun.ip6_unl.ip6_unl_hlim
// #define ip6_hops             ip6_ctlun.ip6_unl.ip6_unl_hops

    u_int32_t unuseful[2]; 
    u_int8_t src[16];
    u_int8_t dst[16];
    // struct in6_addr ip6_src;/* 发送端地址 */
    // struct in6_addr ip6_dst;/* 接收端地址 */
}IPv6Header_t;

//TCP数据报头
typedef struct tagTCPHeader_t
{
    //TCP数据报头
    u_int16 SrcPort; //源端口
    u_int16 DstPort; //目的端口
    u_int32 SeqNO;   //序号
    u_int32 AckNO;   //确认号
} TCPHeader_t;

#endif