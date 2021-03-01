//
// Created by Dong Liu on 20/1/2021.
//

#include "moloch.h"
#include "patricia.h"
#include <inttypes.h>
#include <arpa/inet.h>
#include <errno.h>
extern int                   nxgMProtocol;
extern uint32_t              pluginsCbs;
extern MolochConfig_t        config;

LOCAL  int packetTs;
LOCAL  int mirrorTaskId;
LOCAL  int mirrorDropMode;
LOCAL  int captureTaskId;
LOCAL  int capturePassMode;
LOCAL  int captureDropMode;
LOCAL  int captureTaskModule;

unsigned long * parse_custom_data(MolochPacket_t *packet)
{
    unsigned long custom_field[8] ={0};
    printf("enter parse custom data\n");
    if (packet->mProtocol == nxgMProtocol) {
//        printf("endter======data======%d------%d\n", sizeof(struct ip6_hdr), sizeof(struct ip4_hdr));
        uint8_t *pkt = packet->pkt;
        int pkt_len = packet->pktlen;
        int org_payload_len = packet->payloadLen;
        int payload_off = packet->payloadOffset;
        int payload_len = 0;
        if (org_payload_len < config.captureTruncLen) {
            payload_len = org_payload_len + payload_off;
        } else {
            payload_len = org_payload_len + 4 + 14;
        }

        uint8_t opt = pkt[payload_len];
        int option = (int) opt;
        printf("pktLen:%d, payloadLen:%d, payloadOffload:%d, orgPayloadLen:%d, ipOffset:%d, option======%d\n", pkt_len, payload_len, payload_off, org_payload_len,packet->ipOffset, option);
        int option_len = 0;
        int option_value = 0;
        int option_offset = payload_len;

//        unsigned long custom_field[6] ={0};
        while (option >= 2 && option <= 8) {

            option_len = pkt[option_offset + 1];
            int value_len = option_len - 2;

//            int malloc_len = sizeof(uint8_t) * value_len;
//            uint8_t *value = malloc(malloc_len);
//            int charlen = strlen(value);
//            strncpy(value, pkt, value_len);
//            memcpy(buf+1, &addr1, 4);

//            memcpy(value, pkt+option_offset+1+1, value_len);
//            int number = (int)strtol(value, NULL, 16);
            char hex[16] = {0};
            moloch_sprint_hex_string(hex, pkt + option_offset + 1 + 1, value_len);
//            moloch_print_hex_string(value, malloc_len);
//            for (int i = 0; i < malloc_len; i++) {
//                printf("%u", value[i]);
//            }
//            printf("\n");
//            strncpy(test, pkt+option_offset+1+1, value_len);
//            int int_value = atoui(p);
            long res_value = strtoul(hex, NULL, 16);
            custom_field[option] = res_value;
            printf("======option:%d======%d\n", option, res_value);
            option_offset += option_len;
            option = (int) pkt[option_offset];
        }

        for (int i = 0; i < 8; ++i) {
            printf("parse1 data custom value====index:%d=====value:%lu\n", i, custom_field[i]);
        }
        printf("11111111111111111111111 \n\n");
        moloch_print_hex_string(packet->pkt, packet->pktlen);
    } else {
        printf("Error function======\n");
    }
    return custom_field;
}
/**
 * 回调函数，自定义session的生成规则。注意，这里的session和es里的session不一样，es里的session是满足写条件后写到es，然后自动生成id。多条
 * 对应这里的一条。这里的session对应es里的多条session。
 */
/******************************************************************************/
SUPPRESS_ALIGNMENT
void nxg_create_sessionid(uint8_t *sessionId, MolochPacket_t *packet)
{
    //src_ip+dst_ip+src_port+dst_port+capture+ipportal
    printf("enter nxg create sessionid111111==========\n");
    struct ip           *ip4 = (struct ip*)(packet->pkt + packet->ipOffset);
    struct ip6_hdr      *ip6 = (struct ip6_hdr*)(packet->pkt + packet->ipOffset);
    struct tcphdr       *tcphdr = 0;
    struct udphdr       *udphdr = 0;

    uint16_t port1 = 0;
    uint16_t port2 = 0;
    uint8_t ipProtocol = packet->ipProtocol;
    if (ipProtocol == IPPROTO_TCP) {
        tcphdr = (struct tcphdr *)(packet->pkt + packet->payloadOffset);
        port1 = tcphdr->th_sport;
        port2 = tcphdr->th_dport;
    } else if(ipProtocol == IPPROTO_UDP || ipProtocol == IPPROTO_ICMP || ipProtocol == IPPROTO_ICMPV6){
        udphdr = (struct udphdr *)(packet->pkt + packet->payloadOffset);
        port1 = udphdr->uh_sport;
        port2 = udphdr->uh_dport;
    } else {
        port1 = 0;
        port2 = 0;
    }
    printf("nxg parser proto:%d------port:%d------%d\n", ipProtocol,port1, port2);

//    moloch_print_hex_string(packet->pkt, packet->pktlen);
    int pkt_len = packet->pktlen;
    int ip_len = ntohs(ip4->ip_len);
    int ip6_len = ntohs(ip6->ip6_plen);
    int payload_len = packet->payloadLen;


    if (packet->v6) {
        moloch_session_id6(sessionId, ip6->ip6_src.s6_addr, port1,
                           ip6->ip6_dst.s6_addr, port2);
    } else {
        moloch_session_id(sessionId, ip4->ip_src.s_addr, port1,
                          ip4->ip_dst.s_addr, port2);
    }

    unsigned long *custom_field = parse_custom_data(packet);
    for (int i = 0; i < 8; ++i) {
        printf("after custom value====index:%d=====value:%lu\n", i, custom_field[i]);
    }
    printf("======parser------Protocol:%u\n", ipProtocol);
    memcpy(sessionId+37, &ipProtocol, 1);

    if (custom_field[5] != 0) {
        printf("nxg create sessionid--------------------\n");
        uint8_t *captureId = (uint8_t*)&custom_field[5];
        printf("len:%d, values:%s", sizeof(captureId),  captureId);
        memcpy(sessionId+38, &custom_field[5], sizeof(captureId));
    }

    moloch_print_hex_string(sessionId, MOLOCH_SESSIONID_LEN);
    printf("complete create sessionid------");

}

//create session的回调函数
SUPPRESS_ALIGNMENT
LOCAL MolochPacketRC nxg_packet_enqueue(MolochPacketBatch_t * UNUSED(batch), MolochPacket_t * const packet, const uint8_t *data, int len)
{
    uint8_t sessionId[MOLOCH_SESSIONID_LEN];

    nxg_create_sessionid(sessionId, packet);

    packet->hash = moloch_session_hash(sessionId);
    packet->mProtocol = nxgMProtocol;

    return MOLOCH_PACKET_DO_PROCESS;
}

/******************************************************************************/
/**
 * 回调函数。预处理。比如新的session，这里添加一些自定义的字段。
 */
SUPPRESS_ALIGNMENT
void nxg_pre_process(MolochSession_t *session, MolochPacket_t * const packet, int isNewSession)
{
    struct ip           *ip4 = (struct ip*)(packet->pkt + packet->ipOffset);
    struct ip6_hdr      *ip6 = (struct ip6_hdr*)(packet->pkt + packet->ipOffset);
    struct tcphdr       *tcphdr = 0;
    struct udphdr       *udphdr = 0;

    uint8_t ipProtocol = packet->ipProtocol;
    if(ipProtocol == IPPROTO_TCP) {
        tcphdr = (struct tcphdr *) (packet->pkt + packet->payloadOffset);
        session->port1 = ntohs(tcphdr->th_dport);
        session->port2 = ntohs(tcphdr->th_sport);
        session->tcp_flags |= tcphdr->th_flags;
        if (config.enablePacketFlag) {
            uint16_t flag = 0;
//            if (tcphdr->th_win == 0 && (tcphdr->th_flags & TH_RST) == 0) {
//                session->tcpFlagCnt[MOLOCH_TCPFLAG_SRC_ZERO + packet->direction]++;
//            }

//            if (len < 0)
//                return 1;

            if (tcphdr->th_flags & TH_URG) {
//                session->tcpFlagCnt[MOLOCH_TCPFLAG_URG]++;
                flag = TH_URG;
            }

            if (tcphdr->th_flags & TH_SYN) {
                if (tcphdr->th_flags & TH_ACK) {
                    flag = TH_ACK;
//                    session->tcpFlagCnt[MOLOCH_TCPFLAG_SYN_ACK]++;

                } else {
//                    session->tcpFlagCnt[MOLOCH_TCPFLAG_SYN]++;
                    flag = TH_SYN;
                }
//
//                return 1;
            }

            if (tcphdr->th_flags & TH_RST) {
//                session->tcpFlagCnt[MOLOCH_TCPFLAG_RST]++;
                flag = TH_RST;
            }

            if (tcphdr->th_flags & TH_FIN) {
//                session->tcpFlagCnt[MOLOCH_TCPFLAG_FIN]++;
                flag = TH_FIN;
            }

            if ((tcphdr->th_flags & (TH_FIN | TH_RST | TH_PUSH | TH_SYN | TH_ACK)) == TH_ACK) {
//                session->tcpFlagCnt[MOLOCH_TCPFLAG_ACK]++;
                flag = TH_ACK;
            }

            if (tcphdr->th_flags & TH_PUSH) {
//                session->tcpFlagCnt[MOLOCH_TCPFLAG_PSH]++;
                flag = TH_PUSH;
            }
            g_array_append_val(session->packetFlagArray, flag);
            LOG("Add flag======%d", flag);
        }

        LOG("Support Tcp proto:%d， tcp_flags:%u------%u",  ip4->ip_p, session->tcp_flags, tcphdr->th_flags);
    } else if(ipProtocol == IPPROTO_UDP || ipProtocol == IPPROTO_ICMP || ipProtocol == IPPROTO_ICMPV6) {
        LOG("Support udp proto:%d",  ip4->ip_p);
        udphdr = (struct udphdr *) ((char *) ip4 + packet->payloadOffset);
        session->port1 = ntohs(udphdr->uh_sport);
        session->port2 = ntohs(udphdr->uh_dport);
    } else {
        LOG("Unsupport proto:%d",  ip4->ip_p);
    }
    LOG("NXG pre process session111111======%d------", ip4->ip_p);
    unsigned long *custom_field = parse_custom_data( packet);
    for (int i = 0; i < 8; ++i) {
        printf("pre process custom value====index:%d=====value:%lu\n", i, custom_field[i]);
    }



    if (isNewSession) {
        moloch_session_add_protocol(session, "nxg");
//        moloch_session_add_protocol(session, session->ipProtocol);
        char                   ipsrc[INET6_ADDRSTRLEN];
        char                   ipdst[INET6_ADDRSTRLEN];
        if (IN6_IS_ADDR_V4MAPPED(&session->addr1)) {
            uint32_t ip = MOLOCH_V6_TO_V4(session->addr1);
            snprintf(ipsrc, sizeof(ipsrc), "%u.%u.%u.%u", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
            ip = MOLOCH_V6_TO_V4(session->addr2);
            snprintf(ipdst, sizeof(ipdst), "%u.%u.%u.%u", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
        } else {
            inet_ntop(AF_INET6, &session->addr1, ipsrc, sizeof(ipsrc));
            inet_ntop(AF_INET6, &session->addr2, ipdst, sizeof(ipdst));
        }
//        LOG("SrcIp:%s, DstIp:%s, srcPort:%u, DstPort:%u, protocol:%d, Mode:%d, NodeName:%s", ipsrc, ipdst, session->port1, session->port2, session->ipProtocol,  1, config.nodeName);

//        if (custom_field[2] != 0) {
////            char buf[16];
////            sprintf(buf, "%lu", custom_field[2]);
////            LOG("NXG add field 2======%s, %d", buf, strlen(buf));
//            moloch_field_int_add(packetTs, session, custom_field[2]);
////            moloch_field_string_add(captureIdField, session, buf, strlen(buf), FALSE);
//        }

        if (custom_field[4] != 0) {
            moloch_field_int_add(mirrorTaskId, session, custom_field[4]);
        }

        if (custom_field[5] != 0) {
            moloch_field_int_add(captureTaskId, session, custom_field[5]);
        }



//        if (custom_field[3] != 0) {
//            char buf[16];
//            sprintf(buf, "%lu", custom_field[3]);
//            LOG("NXG add field 3======%s, %d", buf, strlen(buf));
//            moloch_field_int_add(mirrorId, session, custom_field[3]);
//        }

//        if (custom_field[5] != 0) {
//            char buf[16];
//            sprintf(buf, "%lu", custom_field[5]);
//            LOG("NXG add field 5======%s, %d", buf, strlen(buf));
////            moloch_field_string_add(mirrorId, session, buf, strlen(buf), FALSE);
//            moloch_field_int_add(mirrorId, session, custom_field[5]);
//        }

    }

    if (custom_field[3] != 0) {
        moloch_field_int_add(mirrorDropMode, session, custom_field[3]);
    }

    //通过的模块
    if (custom_field[6] != 0) {
        char str[10];
        sprintf(str, "6_%d", custom_field[6]);
        moloch_field_int_add(capturePassMode, session, custom_field[6]);
        moloch_field_string_add(captureTaskModule, session, str, -1, TRUE);
    } else if (custom_field[7] != 0) {
        char str[10];
        sprintf(str, "7_%d", custom_field[7]);
        moloch_field_int_add(captureDropMode, session, custom_field[7]);
        moloch_field_string_add(captureTaskModule, session, str, -1, TRUE);
    } else {
        char str[10]="0_0";
        moloch_field_string_add(captureTaskModule, session, str, -1, TRUE);
    }
}


/******************************************************************************/
int nxg_process(MolochSession_t *session, MolochPacket_t * const packet)
{
    LOG("NXG process session======");
//    const uint8_t *data = packet->pkt + packet->payloadOffset + 8;
//    int            len = packet->payloadLen - 8;
//
//    if (len <= 0)
//        return 1;
//
//    if (session->firstBytesLen[packet->direction] == 0) {
//        session->firstBytesLen[packet->direction] = MIN(8, len);
//        memcpy(session->firstBytes[packet->direction], data, session->firstBytesLen[packet->direction]);
//
//        moloch_parsers_classify_udp(session, data, len, packet->direction);
//
//        if (config.yara && config.yaraEveryPacket && !session->stopYara) {
//            moloch_yara_execute(session, data, len, 0);
//        }
//    }
//
//    int i;
//    for (i = 0; i < session->parserNum; i++) {
//        if (session->parserInfo[i].parserFunc) {
//            int consumed = session->parserInfo[i].parserFunc(session, session->parserInfo[i].uw, data, len, packet->direction);
//            if (consumed == MOLOCH_PARSER_UNREGISTER) {
//                if (session->parserInfo[i].parserFreeFunc) {
//                    session->parserInfo[i].parserFreeFunc(session, session->parserInfo[i].uw);
//                }
//                memset(&session->parserInfo[i], 0, sizeof(session->parserInfo[i]));
//                continue;
//            }
//        }
//    }
//
//    if (pluginsCbs & MOLOCH_PLUGIN_UDP)
//        moloch_plugins_cb_udp(session, data, len, packet->direction);

    return 1;
}

void moloch_parser_init()
{
    moloch_packet_set_ip_cb(MOLOCH_IPPROTO_NXG, nxg_packet_enqueue);

//    moloch_packet_set_ip_cb(IPPROTO_ESP, esp_packet_enqueue);
    nxgMProtocol = moloch_mprotocol_register("nxg",
                                             SESSION_OTHER,
                                             nxg_create_sessionid,
                                             nxg_pre_process,
                                             nxg_process,
                                             NULL);


//    LOCAL  int packetTs;
//    LOCAL  int mirrorTaskId;
//    LOCAL  int mirrorDropMode;
//    LOCAL  int captureTaskId;
//    LOCAL  int capturePassMode;
//    LOCAL  int captureDropMode;
    //声明新增哪些字段

    //captureid
    captureTaskId = moloch_field_define("general", "integer",
                                        "captureId", "CaptureId", "captureId",
                                        "Nxg capture id",
                                        MOLOCH_FIELD_TYPE_INT,  MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
                                        (char *)NULL);

    capturePassMode = moloch_field_define("general", "integer",
                                          "nxg.capturepass", "CapturePassMode", "nxg.capturepass",
                                          "Nxg capture pass mode",
                                          MOLOCH_FIELD_TYPE_INT_GHASH,  MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
                                          (char *)NULL);

    captureDropMode = moloch_field_define("nxg", "integer",
                                          "nxg.capturedrop", "CaptureDropMode", "nxg.capturedrop",
                                          "Nxg capture drop mode",
                                          MOLOCH_FIELD_TYPE_INT_GHASH,  MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
                                          (char *)NULL);

    captureTaskModule = moloch_field_define("general", "termfield",
                                        "packetModule", "Capture Module", "packetModule",
                                        "Nxg capture drop module",
                                        MOLOCH_FIELD_TYPE_STR_ARRAY,  MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
                                        (char *)NULL);
    printf("-------------xxxxxx----------%d\n", captureTaskModule);

    //mirror丢包模块
    mirrorDropMode = moloch_field_define("general", "integer",
                                     "mirrorModule", "mirrorModule", "mirrorModule",
                                     "Nxg mirror drop mode",
                                     MOLOCH_FIELD_TYPE_INT_ARRAY,  MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
                                     (char *)NULL);
    //mirrorid
    mirrorTaskId = moloch_field_define("general", "integer",
                                   "mirrorId", "MirrorId", "mirrorId",
                                   "Nxg drop mirror id",
                                   MOLOCH_FIELD_TYPE_INT,  MOLOCH_FIELD_FLAG_LINKED_SESSIONS,
                                   (char *)NULL);


}

