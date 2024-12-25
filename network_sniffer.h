// File: network_sniffer.h
// Description: Header file for the Network Sniffer tool.

#ifndef NETWORK_SNIFFER_H
#define NETWORK_SNIFFER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <stdarg.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <ctype.h>
#include "cJSON/cJSON.h"
#define MAX_DOMAINS 100
#define ETHERNET_HEADER_SIZE 14
#define IP_HEADER_SIZE 20
#define UDP_HEADER_SIZE 8
#define DNS_HEADER_SIZE 12
#define MAX_STACK_SIZE 100

#define RESET_COLOR   "\033[0m"
#define RED_COLOR     "\033[1;31m"
#define GREEN_COLOR   "\033[1;32m"
#define YELLOW_COLOR  "\033[1;33m"

extern int sniffing;

// Structures
typedef struct {
    char domain_name[256];
    char resolved_ipv4[16];
    char resolved_ipv6[40];
    char cname_record[256];
} DNSRecord;

typedef struct {
    DNSRecord stack[MAX_DOMAINS];
    int top;
} DNSStack;

// Function Prototypes
void list_interfaces();
void stop_sniffing(int sig);
void decode_domain_name(const unsigned char *data, int *offset, int data_len, char *domain, int domain_len);
int is_domain_resolved(const char *domain);
void mark_domain_as_resolved(const char *domain);
void resolve_with_nslookup(const char *domain);
void parse_dns_packet(const unsigned char *dns_data, int data_len);
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);
void init_stack(DNSStack *s);
int is_empty(DNSStack *s);
int is_full(DNSStack *s);
void push(DNSStack *s, const char *domain, const char *ipv4, const char *ipv6, const char *cname);
int pop(DNSStack *s, DNSRecord *record);
int peek(DNSStack *s, DNSRecord *record);
void display_stack(DNSStack *s);
void log_printf(const char *format, ...);
void writeFile(const char *filename, const char *content);
char *readFile(const char *filename);
void parse_dns_packet(const unsigned char *dns_data, int data_len);
void print_banner();
#endif // NETWORK_SNIFFER_H