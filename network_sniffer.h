/*
 * File: network_sniffer.h
 * Description: This header file defines the interface for the network sniffer application. 
 *              It includes function declarations, data structures, constants, and external 
 *              dependencies necessary for the implementation of network sniffing and packet 
 *              processing. This file serves as the primary interface between the sniffer module 
 *              and other parts of the application.
 *
 * Author: [Your Name]
 * Date: [Current Date or Creation Date]
 *
 * License: [Your License Type, e.g., MIT, GPL, etc.]
 *
 * Dependencies:
 *   - pcap library (for packet capturing)
 *   - standard C libraries (stdio, stdlib, string, etc.)
 *   - [Any other libraries used, if applicable]
 *
 * Usage:
 *   - This file should be included in source files that require network sniffing capabilities.
 *   - It provides functions for listing network interfaces, starting/stopping sniffing, and
 *     processing packets. The file also contains macros for error handling and logging.
 *   - Functions like `list_interfaces()` and `packet_handler()` allow easy integration with
 *     packet capture systems, and the `DNSStack` and `DNSRecord` structures are used to store
 *     DNS data.
 *
 * Change History:
 *   [Date] - Initial version.
 *   [Date] - [Changes made in the file, bug fixes, or added features].
 */


#ifndef NETWORK_SNIFFER_H
#define NETWORK_SNIFFER_H

// Include necessary system and library headers
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>  // Packet capture library
#include <arpa/inet.h>  // Networking definitions
#include <signal.h>  // Signal handling
#include <time.h>  // Time functions
#include <stdarg.h>  // Variable argument list
#include <ifaddrs.h>  // Interface address structures
#include <net/if_dl.h>  // Link layer address
#include <ctype.h>  // Character handling
#include "cJSON/cJSON.h"  // JSON parsing library

// Define constants for various sizes and limits
#define MAX_DOMAINS 100  // Maximum number of domains to track
#define ETHERNET_HEADER_SIZE 14  // Ethernet header size
#define IP_HEADER_SIZE 20  // IP header size
#define UDP_HEADER_SIZE 8  // UDP header size
#define DNS_HEADER_SIZE 12  // DNS header size
#define MAX_STACK_SIZE 100  // Maximum size of the DNS stack

// Define color constants for terminal output
#define RESET_COLOR   "\033[0m"  // Reset text color
#define RED_COLOR     "\033[1;31m"  // Red text color
#define GREEN_COLOR   "\033[1;32m"  // Green text color
#define YELLOW_COLOR  "\033[1;33m"  // Yellow text color

// Declare an external variable used for sniffing state
extern int sniffing;

// Define the DNSRecord structure to store DNS query/response details
typedef struct {
    char domain_name[256];  // Domain name
    char resolved_ipv4[16];  // Resolved IPv4 address
    char resolved_ipv6[40];  // Resolved IPv6 address
    char cname_record[256];  // CNAME record, if applicable
} DNSRecord;

// Define the DNSStack structure to store a stack of DNS records
typedef struct {
    DNSRecord stack[MAX_DOMAINS];  // Array of DNS records
    int top;  // Top index of the stack
} DNSStack;

// Function Prototypes: Declarations for various functions used in the program

// Function to list available network interfaces
void list_interfaces();

// Function to stop sniffing on signal
void stop_sniffing(int sig);

// Function to decode a domain name from DNS packet data
void decode_domain_name(const unsigned char *data, int *offset, int data_len, char *domain, int domain_len);

// Function to check if a domain has already been resolved
int is_domain_resolved(const char *domain);

// Function to mark a domain as resolved
void mark_domain_as_resolved(const char *domain);

// Function to resolve a domain using nslookup
void resolve_with_nslookup(const char *domain);

// Function to parse a DNS packet and process its information
void parse_dns_packet(const unsigned char *dns_data, int data_len);

// Function to handle incoming packets
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet);

// Stack-related functions for managing the DNS record stack
void init_stack(DNSStack *s);  // Initialize the stack
int is_empty(DNSStack *s);  // Check if the stack is empty
int is_full(DNSStack *s);  // Check if the stack is full
void push(DNSStack *s, const char *domain, const char *ipv4, const char *ipv6, const char *cname);  // Push a record to the stack
int pop(DNSStack *s, DNSRecord *record);  // Pop a record from the stack
int peek(DNSStack *s, DNSRecord *record);  // Peek the top record without removing it

// Function to display the DNS stack
void display_stack(DNSStack *s);

// Function to log formatted messages to the log file and console
void log_printf(const char *format, ...);

// File handling functions
void writeFile(const char *filename, const char *content);  // Write content to a file
char *readFile(const char *filename);  // Read content from a file

// Banner function to print program information
void print_banner();

#endif // NETWORK_SNIFFER_H
