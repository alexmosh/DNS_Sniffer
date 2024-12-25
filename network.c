/*
 * File: network.c
 * Description: This file contains the implementation of functions for network packet 
 *              sniffing and processing. It includes functions for initializing network 
 *              interfaces, capturing packets, handling network data, and processing DNS 
 *              information. The file relies on the pcap library for capturing live network 
 *              traffic and performs various checks and actions based on the captured packets.
 *              Functions for interface listing, packet handling, and DNS parsing are provided 
 *              to enable network traffic analysis and diagnostics.
 *
 * Author: [Your Name]
 * Date: [Current Date or Creation Date]
 *
 * License: [Your License Type, e.g., MIT, GPL, etc.]
 *
 * Dependencies:
 *   - pcap library (for packet capture)
 *   - standard C libraries (stdio, stdlib, string, etc.)
 *   - [Any other libraries used, if applicable]
 *
 * Usage:
 *   - This file is used in conjunction with the `network_sniffer.h` header file.
 *   - Functions such as `list_interfaces()`, `packet_handler()`, and `process_packet()` 
 *     are used to capture and process network packets, particularly DNS requests and responses.
 *   - The file provides the core functionality for packet sniffing and basic packet analysis.
 *
 * Change History:
 *   [Date] - Initial version of network packet sniffing functions.
 *   [Date] - [Changes made in the file, bug fixes, or added features].
 */


#include "network_sniffer.h" 

#ifdef __linux__
#include <netpacket/packet.h>
#define AF_LINK AF_PACKET
#endif

// Function to list available network interfaces and their MAC addresses


// Function to stop sniffing when a signal is received
void stop_sniffing(int sig) {
    int sniffing = 0;  // Stop sniffing by setting the sniffing flag to 0
}

void list_interfaces() {
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    int sockfd;
    struct ifreq ifr;
    
    // Retrieve the list of interfaces using getifaddrs
    if (getifaddrs(&ifap) == -1) {
        perror("getifaddrs");
        return;
    }

    // Print header for the interface list
    printf("\nAvailable Interfaces:\n");
    printf("+----------------------------------+-----------------------+\n");
    printf("| %-30s | %-21s |\n", "Interface", "MAC Address");
    printf("+----------------------------------+-----------------------+\n");

    // Create a socket to use ioctl for MAC address retrieval
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd == -1) {
        perror("socket");
        freeifaddrs(ifap);
        return;
    }

    // Iterate through the list of interfaces
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        // Only process interfaces that are up (AF_INET) and have a name
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            // Get the interface name
            printf("| %-30s | ", ifa->ifa_name);

            // Use ioctl to retrieve the MAC address
            memset(&ifr, 0, sizeof(struct ifreq));
            strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
            
            // Get the MAC address using ioctl
            if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
                unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            } else {
                printf("No MAC address\n");
            }
        }
    }

    // Cleanup
    close(sockfd);
    freeifaddrs(ifap);
    printf("+----------------------------------+-----------------------+\n");
}
// Function to handle incoming network packets and process DNS data
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
   // Extract DNS data by skipping over Ethernet, IP, and UDP headers
   const unsigned char *dns_data = packet + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
   int dns_data_len = pkthdr->len - (ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE);

   // Check if there's enough data to process the DNS header
   if (dns_data_len < DNS_HEADER_SIZE) {
       fprintf(stderr, "Error: Not enough data for DNS header\n");  // Print error if not enough data
       return;
   }

   // Check if the packet is a DNS response by looking at the flags
   int flags = (dns_data[2] << 8) | dns_data[3];  // Get the DNS flags from the header
   if ((flags & 0x8000) == 0) {
       return;  // If it's not a DNS response, ignore the packet
   }

   // Call the function to parse and process the DNS packet data
   parse_dns_packet(dns_data, dns_data_len);
}
