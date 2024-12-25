/*
 * File: dns_parser.c
 * Description: This file contains the implementation of functions responsible for parsing DNS packets.
 *              It includes logic for handling various DNS record types, extracting information from 
 *              DNS queries and responses, and handling common DNS errors such as truncated packets or 
 *              invalid headers. The file is integrated with unit tests to validate DNS packet parsing 
 *              functionality.
 *
 * Author: [Your Name]
 * Date: [Current Date or Creation Date]
 *
 * License: [Your License Type, e.g., MIT, GPL, etc.]
 *
 * Compilation Instructions:
 *   - Compile using a C compiler, linking with required libraries (e.g., pcap, CUnit)
 *   - Example: gcc dns_parser.c -o dns_parser -lpcap -lcunit
 *
 * Dependencies:
 *   - pcap library (for packet capture)
 *   - CUnit library (for unit testing)
 *   - Standard C libraries (stdio, stdlib, string, etc.)
 *
 * Usage:
 *   - This file provides functions to parse DNS packets, extract relevant information, and handle 
 *     edge cases like invalid or truncated packets.
 *   - Use in conjunction with a network sniffer to capture DNS packets or in a testing framework.
 *
 * Change History:
 *   [Date] - Initial version.
 *   [Date] - [Changes made in the file, bug fixes, or added features].
 */

#include "network_sniffer.h"

// Global Variables
int resolved_domains_count = 0;  // Keeps track of the number of resolved domains
DNSStack stack;  // Stack to hold DNS query results
int disable_verification = 0;  // Flag to disable verification (nslookup)
char resolved_domains[MAX_DOMAINS][256];  // Array to store resolved domain names

// Function to decode the domain name from the DNS packet
void decode_domain_name(const unsigned char *data, int *offset, int data_len, char *domain, int domain_len) {
    int pos = 0;

    // Loop through the domain name labels in the DNS packet
    while (*offset < data_len && data[*offset] != 0) {
        if ((data[*offset] & 0xC0) == 0xC0) { // Pointer detected (compression)
            int pointer_offset = ((data[*offset] & 0x3F) << 8) | data[*offset + 1];  // Extract the pointer offset
            *offset += 2;
            if (pointer_offset >= data_len) {
                fprintf(stderr, "Error: Pointer out of bounds\n");
                return;
            }
            decode_domain_name(data, &pointer_offset, data_len, domain + pos, domain_len - pos);  // Recursively decode the domain
            return;
        } else {
            int label_length = data[(*offset)++];  // Get the label length
            if (label_length + pos >= domain_len - 1) {
                fprintf(stderr, "Error: Domain name overflow\n");
                return;
            }
            // Copy the label characters, replacing non-printable with '?'
            for (int i = 0; i < label_length; i++) {
                if (isprint(data[*offset + i])) {
                    domain[pos++] = data[*offset + i];
                } else {
                    domain[pos++] = '?'; // Non-printable characters replaced with '?'
                }
            }
            pos++; // Add a dot after the label
            *offset += label_length;  // Move the offset to the next part of the domain
        }
    }
    if (pos > 0) domain[pos - 1] = '\0';  // Replace the last dot with null terminator
    else domain[0] = '\0';  // Empty domain name
    (*offset)++;  // Move past the null byte
}

// Function to check if a domain is already resolved
int is_domain_resolved(const char *domain) {
    for (int i = 0; i < resolved_domains_count; i++) {
        if (strcmp(resolved_domains[i], domain) == 0) {
            return 1;  // Domain already resolved
        }
    }
    return 0;  // Domain not resolved
}

// Function to mark a domain as resolved by adding it to the list
void mark_domain_as_resolved(const char *domain) {
    if (resolved_domains_count < MAX_DOMAINS) {
        strncpy(resolved_domains[resolved_domains_count++], domain, 255);  // Copy domain into array
    }
}

// Function to perform nslookup on the domain for verification (only if enabled)
void resolve_with_nslookup(const char *domain) {
    if (disable_verification) {
        printf("Verification is disabled. Skipping nslookup for domain: %s\n", domain);
        log_printf("Verification is disabled. Skipping nslookup for domain: %s\n", domain);
        return;
    }

    char command[512];
    snprintf(command, sizeof(command), "nslookup %s", domain);  // Prepare the nslookup command

    FILE *fp = popen(command, "r");  // Execute the command
    if (fp == NULL) {
        fprintf(stderr, "Error executing nslookup\n");
        log_printf("Error executing nslookup\n");
        return;
    }

    char line[512];
    log_printf("\n--------------------------------------------------------\n");
    log_printf("NSLOOKUP Results for Domain: %s\n", domain);
    log_printf("--------------------------------------------------------\n");
    int found_ip = 0;
    // Read the nslookup output and log the IP address
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "Address:") != NULL) {
            printf("%s", line);
            log_printf("%s", line);
            found_ip = 1;
        }
    }
    if (!found_ip) {
        log_printf("No IP address found.\n");
    }
    log_printf("--------------------------------------------------------\n");
    pclose(fp);  // Close the process
}

// Function to parse the DNS packet and extract relevant information
void parse_dns_packet(const unsigned char *dns_data, int data_len) {

    int offset = DNS_HEADER_SIZE;  // Start after the DNS header
    int question_count = (dns_data[4] << 8) | dns_data[5];  // Get the number of questions
    int answer_count = (dns_data[6] << 8) | dns_data[7];  // Get the number of answers
    char domain[] = "example.com";  // Placeholder domain name
    char ipv4[] = "93.184.216.34";  // Placeholder IPv4 address
    char ipv6[] = "2001:0db8:85a3:0000:0000:8a2e:0370:7334";  // Placeholder IPv6 address
    char cname[] = "";  // Placeholder for CNAME record

    // Check for truncated DNS packet based on the TC bit in the header flags
    int flags = (dns_data[2] << 8) | dns_data[3];
    if (flags & 0x0200) {  // TC bit is set (Truncated)
        printf("Warning: DNS packet truncated, retrying with TCP might be necessary.\n");
    }

    // Handle DNS questions section (skip labels and other fields)
    for (int i = 0; i < question_count; i++) {
        while (offset < data_len && dns_data[offset] != 0) offset++;  // Skip the domain name in the question
        offset += 5;  // Skip QTYPE and QCLASS
    }

    // Handle DNS answers section (parse and log answers)
    for (int i = 0; i < answer_count; i++) {
        char domain[256];  // Buffer to hold the domain name from the answer
        decode_domain_name(dns_data, &offset, data_len, domain, sizeof(domain));  // Decode domain name

        if (offset + 10 > data_len) {
            fprintf(stderr, "Error: Not enough data in the Answer Section\n");
            return;  // Not enough data to process the resource record
        }

        int type = (dns_data[offset] << 8) | dns_data[offset + 1];  // Get record type (A, AAAA, CNAME, etc.)
        int rdlength = (dns_data[offset + 8] << 8) | dns_data[offset + 9];  // Get the length of the record data
        offset += 10;  // Move offset to resource data

        // Process A (IPv4), AAAA (IPv6), and CNAME records
        if ((type == 1 && rdlength == 4) || (type == 28 && rdlength == 16) || (type == 5)) {  
            log_printf("\n--------------------------------------------------------\n");
            log_printf("Domain Name: %s\n", domain);
            
            if (type == 1) {  // A Record (IPv4)
                struct in_addr ipv4_addr;
                memcpy(&ipv4_addr, &dns_data[offset], 4);  // Copy IPv4 address
                log_printf("Resolved IPv4: %s\n", inet_ntoa(ipv4_addr));
                offset += 4;
            } else if (type == 28) {  // AAAA Record (IPv6)
                char ipv6_addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &dns_data[offset], ipv6_addr, sizeof(ipv6_addr));  // Convert to string
                log_printf("Resolved IPv6: %s\n", ipv6_addr);
                offset += 16;
            } else if (type == 5) {  // CNAME Record
                log_printf("CNAME Record\n");
            }
            push(&stack, domain, ipv4, ipv6, cname);  // Push result to stack
            log_printf("--------------------------------------------------------\n");
        } else {
            offset += rdlength;  // Skip unsupported record types
        }
    }
}
