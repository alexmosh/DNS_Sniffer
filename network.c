// File: network.c
// Description: Functions related to network operations.

#include "network_sniffer.h" 

void list_interfaces() {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *interfaces, *temp;


   if (pcap_findalldevs(&interfaces, errbuf) == -1) {
       fprintf(stderr, "Error finding devices: %s\n", errbuf);
       return;
   }


   // Print the header of the table
   log_printf("\nAvailable Interfaces:\n");
   log_printf("+----------------------------------+-----------------------+\n");
   log_printf("| %-30s | %-21s |\n", "Interface", "Hardware (MAC) Address");
   log_printf("+----------------------------------+-----------------------+\n");


   // Get the list of all interfaces on the system
   struct ifaddrs *ifap, *ifa;
   if (getifaddrs(&ifap) == -1) {
       perror("getifaddrs");
       return;
   }


   // Iterate through the interfaces and print them in the table
   for (temp = interfaces; temp; temp = temp->next) {
       char mac_addr_str[18] = "00:00:00:00:00:00"; // Default MAC address (in case it can't be retrieved)


       // Loop through the list of interfaces to find the MAC address
       for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
           if (ifa->ifa_name && strcmp(ifa->ifa_name, temp->name) == 0 &&
               ifa->ifa_addr->sa_family == AF_LINK) { // AF_LINK indicates a MAC address
               struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
               unsigned char *mac = (unsigned char *)LLADDR(sdl);
               log_printf("+--------------------------------------------------------+\n");
               snprintf(mac_addr_str, sizeof(mac_addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
               break;
           }
       }


       // Print interface name and MAC address in table format
       log_printf("| %-30s | %-21s |\n", temp->name, mac_addr_str);
   }


   log_printf("+----------------------------------+-----------------------+\n");


   pcap_freealldevs(interfaces);
   freeifaddrs(ifap);
}


void stop_sniffing(int sig) {
    sniffing = 0;
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
   const unsigned char *dns_data = packet + ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE;
   int dns_data_len = pkthdr->len - (ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + UDP_HEADER_SIZE);


   if (dns_data_len < DNS_HEADER_SIZE) {
       fprintf(stderr, "Error: Not enough data for DNS header\n");
       return;
   }


   int flags = (dns_data[2] << 8) | dns_data[3];
   if ((flags & 0x8000) == 0) {
       return; // Not a DNS response packet
   }


   parse_dns_packet(dns_data, dns_data_len);
}

