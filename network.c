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

// Function to list available network interfaces and their MAC addresses
void list_interfaces() {
   char errbuf[PCAP_ERRBUF_SIZE];  // Buffer to hold error messages from pcap functions
   pcap_if_t *interfaces, *temp;  // Pointers for the list of interfaces and the iterator

   // Retrieve all available network interfaces using pcap
   if (pcap_findalldevs(&interfaces, errbuf) == -1) {
       fprintf(stderr, "Error finding devices: %s\n", errbuf);  // Error message if no interfaces found
       return;
   }

   // Print the header of the interface list table
   log_printf("\nAvailable Interfaces:\n");
   log_printf("+----------------------------------+-----------------------+\n");
   log_printf("| %-30s | %-21s |\n", "Interface", "Hardware (MAC) Address");
   log_printf("+----------------------------------+-----------------------+\n");

   // Get the list of all interfaces and their associated addresses
   struct ifaddrs *ifap, *ifa;  // Pointers to interface addresses
   if (getifaddrs(&ifap) == -1) {
       perror("getifaddrs");  // Error retrieving interface addresses
       return;
   }

   // Iterate through the available network interfaces and find their MAC addresses
   for (temp = interfaces; temp; temp = temp->next) {
       char mac_addr_str[18] = "00:00:00:00:00:00";  // Default MAC address if not found

       // Loop through the list of interface addresses to match the interface and get MAC address
       for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
           // If the interface name matches and the address is of type AF_LINK (MAC address)
           if (ifa->ifa_name && strcmp(ifa->ifa_name, temp->name) == 0 &&
               ifa->ifa_addr->sa_family == AF_LINK) {  // AF_LINK denotes a MAC address
               struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;  // Get the sockaddr_dl structure for MAC
               unsigned char *mac = (unsigned char *)LLADDR(sdl);  // Extract the MAC address from sockaddr_dl
               log_printf("+--------------------------------------------------------+\n");
               // Format the MAC address into a readable string
               snprintf(mac_addr_str, sizeof(mac_addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
               break;  // Exit the loop once the MAC address is found
           }
       }

       // Print the interface name along with its corresponding MAC address
       log_printf("| %-30s | %-21s |\n", temp->name, mac_addr_str);
   }

   // Print the footer of the table after listing interfaces
   log_printf("+----------------------------------+-----------------------+\n");

   // Clean up allocated resources for interfaces and address list
   pcap_freealldevs(interfaces);  // Free the list of interfaces retrieved by pcap
   freeifaddrs(ifap);  // Free the list of interface addresses
}

// Function to stop sniffing when a signal is received
void stop_sniffing(int sig) {
    int sniffing = 0;  // Stop sniffing by setting the sniffing flag to 0
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
