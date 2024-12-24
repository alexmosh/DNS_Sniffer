// File: dns_parser.c
// Description: Functions related to DNS packet parsing.

#include "network_sniffer.h"

int resolved_domains_count = 0;
DNSStack stack;
int disable_verification = 0;
char resolved_domains[MAX_DOMAINS][256];

void decode_domain_name(const unsigned char *data, int *offset, int data_len, char *domain, int domain_len) {
    int pos = 0;


    while (*offset < data_len && data[*offset] != 0) {
        if ((data[*offset] & 0xC0) == 0xC0) { // Pointer detected
            int pointer_offset = ((data[*offset] & 0x3F) << 8) | data[*offset + 1];
            *offset += 2;
            if (pointer_offset >= data_len) {
                fprintf(stderr, "Error: Pointer out of bounds\n");
                return;
            }
            decode_domain_name(data, &pointer_offset, data_len, domain + pos, domain_len - pos);
            return;
        } else {
            int label_length = data[(*offset)++];
            if (label_length + pos >= domain_len - 1) {
                fprintf(stderr, "Error: Domain name overflow\n");
                return;
            }
            // Copy label and ensure printable characters only
            for (int i = 0; i < label_length; i++) {
                if (isprint(data[*offset + i])) {
                    domain[pos++] = data[*offset + i];
                } else {
                    domain[pos++] = '?'; // Replace non-printable with ?
                }
            }
            pos++; // Add dot after label
            *offset += label_length;
        }
    }
    if (pos > 0) domain[pos - 1] = '\0'; // Replace last dot with null terminator
    else domain[0] = '\0';
    (*offset)++;
}


int is_domain_resolved(const char *domain) {
    for (int i = 0; i < resolved_domains_count; i++) {
        if (strcmp(resolved_domains[i], domain) == 0) {
            return 1; // Domain already resolved
        }
    }
    return 0;
}

void mark_domain_as_resolved(const char *domain) {
    if (resolved_domains_count < MAX_DOMAINS) {
        strncpy(resolved_domains[resolved_domains_count++], domain, 255);
    }
}

void resolve_with_nslookup(const char *domain) {
    if (disable_verification) {
        printf("Verification is disabled. Skipping nslookup for domain: %s\n", domain);
        log_printf("Verification is disabled. Skipping nslookup for domain: %s\n", domain);
        return;
    }

    char command[512];
    snprintf(command, sizeof(command), "nslookup %s", domain);

    FILE *fp = popen(command, "r");
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
    pclose(fp);
}

void parse_dns_packet(const unsigned char *dns_data, int data_len) {

    int offset = DNS_HEADER_SIZE; // Start after DNS header
    int question_count = (dns_data[4] << 8) | dns_data[5];
    int answer_count = (dns_data[6] << 8) | dns_data[7];
    char domain[] = "example.com";
    char ipv4[] = "93.184.216.34";  // example IPv4 address
    char ipv6[] = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"; // example IPv6 address
    char cname[] = "";
    // Check for truncation in the DNS header flags
    int flags = (dns_data[2] << 8) | dns_data[3];
    if (flags & 0x0200) { // TC bit (Truncated)
        printf("Warning: DNS packet truncated, retrying with TCP might be necessary.\n");
    }

    // Handle questions
    for (int i = 0; i < question_count; i++) {
        while (offset < data_len && dns_data[offset] != 0) offset++;
        offset += 5; // Skip null byte, QTYPE, QCLASS
    }

    // Handle answers
    for (int i = 0; i < answer_count; i++) {
        char domain[256];

        decode_domain_name(dns_data, &offset, data_len, domain, sizeof(domain));
        if (offset + 10 > data_len) {
            fprintf(stderr, "Error: Not enough data in the Answer Section\n");
            return;  // Not enough data to read the resource record
        }

        int type = (dns_data[offset] << 8) | dns_data[offset + 1];
        int rdlength = (dns_data[offset + 8] << 8) | dns_data[offset + 9];
        offset += 10;

        if ((type == 1 && rdlength == 4) || // A Record (IPv4)
            (type == 28 && rdlength == 16) || // AAAA Record (IPv6)
            (type == 5)) { // CNAME Record
            log_printf("\n--------------------------------------------------------\n");
            log_printf("Domain Name: %s\n", domain);
            
            if (type == 1) {
                struct in_addr ipv4_addr;
                memcpy(&ipv4_addr, &dns_data[offset], 4);
                log_printf("Resolved IPv4: %s\n", inet_ntoa(ipv4_addr));
               
    
                offset += 4;
            } else if (type == 28) {
                char ipv6_addr[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &dns_data[offset], ipv6_addr, sizeof(ipv6_addr));
                log_printf("Resolved IPv6: %s\n", ipv6_addr);
                
                offset += 16;
            } else if (type == 5) {
                log_printf("CNAME Record\n");
            }
            push(&stack, domain, ipv4, ipv6,cname);
            log_printf("--------------------------------------------------------\n");
        } else {
            offset += rdlength; // Skip unsupported record types
        }
    }
}
