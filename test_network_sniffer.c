#include "network_sniffer.h"
#include "/opt/homebrew/Cellar/cunit/2.1-3/include/CUnit/CUnit.h"
#include "/opt/homebrew/Cellar/cunit/2.1-3/include/CUnit/Basic.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ifaddrs.h>


extern FILE *log_file;
struct ifaddrs *ifap, *ifa;
struct sockaddr_in *sa;
char *addr;

// Test for stack operations
void test_stack_operations(void) {
    DNSStack stack;
    DNSRecord record;
    
    init_stack(&stack);
    
    // Push record to stack
    push(&stack, "example.com", "93.184.216.34", "2001:0db8::", "cname.example.com");
    CU_ASSERT_EQUAL(stack.top, 0);
    
    // Pop record from stack
    CU_ASSERT_TRUE(pop(&stack, &record));
    CU_ASSERT_STRING_EQUAL(record.domain_name, "example.com");
    CU_ASSERT_STRING_EQUAL(record.resolved_ipv4, "93.184.216.34");
    CU_ASSERT_STRING_EQUAL(record.resolved_ipv6, "2001:0db8::");
    CU_ASSERT_STRING_EQUAL(record.cname_record, "cname.example.com");
    
    // Stack should be empty now
    CU_ASSERT_EQUAL(stack.top, -1);
}

// Test for DNS parsing functionality
void test_dns_parsing(void) {
    unsigned char *mock_dns_packet = malloc(4); // Allocate memory
if (!mock_dns_packet) {
    perror("Memory allocation failed");
    exit(EXIT_FAILURE);
}
mock_dns_packet[0] = 0x01;  // ID;
mock_dns_packet[1] = 0x80;  // Flags;
mock_dns_packet[2] = 0x01;  // Questions
mock_dns_packet[3] = 0x01;  // Answer RRs
int data_len = 4;
    unsigned char mock_dns_packet1[] = {
        // Mock DNS Header (simplified for test)
        0x00, 0x01,  // ID
        0x81, 0x80,  // Flags
        0x00, 0x01,  // Questions
        0x00, 0x01,  // Answer RRs
        0x00, 0x00,  // Authority RRs
        0x00, 0x00,  // Additional RRs
        // Domain Question (example.com)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        
        // Answer (A record, 93.184.216.34)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x04, 
        0x5D, 0xB8, 0xD8, 0x22  // IP: 93.184.216.34
    };
    
   // log_printf("Parsing DNS packet, data length: %d", data_len);
 
    parse_dns_packet(mock_dns_packet, data_len);
    
    // Check if DNS parsing logic works as expected (you can use mocks or assert values)
    // Add actual asserts based on how you structure DNS parsing
}

// Test for truncated DNS packet
void test_dns_parsing_truncated(void) {
    unsigned char mock_dns_packet[] = {
        // Mock DNS Header (simplified for test)
        0x00, 0x01,  // ID
        0x81, 0x80,  // Flags (set TC bit for truncation)
        0x00, 0x01,  // Questions
        0x00, 0x01,  // Answer RRs
        0x00, 0x00,  // Authority RRs
        0x00, 0x00,  // Additional RRs
        // Domain Question (example.com)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        
        // Incomplete Answer (cut off before full record)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01  // Truncated, missing actual answer data
    };
    
    printf("Test: Truncated DNS Packet\n");
    parse_dns_packet(mock_dns_packet, sizeof(mock_dns_packet));
}

// Test for invalid DNS header (invalid question count)
void test_dns_parsing_invalid_header(void) {
    unsigned char mock_dns_packet[] = {
        // Mock DNS Header (simplified for test)
        0x00, 0x01,  // ID
        0x81, 0x80,  // Flags
        0x00, 0xFF,  // Invalid Questions (should be 1)
        0x00, 0x01,  // Answer RRs
        0x00, 0x00,  // Authority RRs
        0x00, 0x00,  // Additional RRs
        // Domain Question (example.com)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        
        // Answer (A record, 93.184.216.34)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x04, 
        0x5D, 0xB8, 0xD8, 0x22  // IP: 93.184.216.34
    };
    
    printf("Test: Invalid DNS Header (Invalid Question Count)\n");
    parse_dns_packet(mock_dns_packet, sizeof(mock_dns_packet));
}

// Test for invalid domain name
void test_dns_parsing_invalid_domain(void) {
    unsigned char mock_dns_packet[] = {
        // Mock DNS Header
        0x00, 0x01,  // ID
        0x81, 0x80,  // Flags
        0x00, 0x01,  // Questions
        0x00, 0x01,  // Answer RRs
        0x00, 0x00,  // Authority RRs
        0x00, 0x00,  // Additional RRs
        // Invalid Domain Question (missing null terminator)
        0x05, 'e', 'x', 'a', 'm', 'p', 0x00, // Invalid domain, no final null byte
        0x00, 0x01, 0x00, 0x01,
        
        // Answer (A record, 93.184.216.34)
        0x05, 'e', 'x', 'a', 'm', 'p', 0x00, // Domain
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x04, 
        0x5D, 0xB8, 0xD8, 0x22  // IP: 93.184.216.34
    };
    
    printf("Test: Invalid Domain Name\n");
    parse_dns_packet(mock_dns_packet, sizeof(mock_dns_packet));
}

// Test for invalid DNS record type
void test_dns_parsing_invalid_record_type(void) {
    unsigned char mock_dns_packet[] = {
        // Mock DNS Header
        0x00, 0x01,  // ID
        0x81, 0x80,  // Flags
        0x00, 0x01,  // Questions
        0x00, 0x01,  // Answer RRs
        0x00, 0x00,  // Authority RRs
        0x00, 0x00,  // Additional RRs
        // Domain Question (example.com)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        
        // Invalid Record Type (Record Type: 0xFFFF)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0xFF, 0xFF, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x04, 
        0x5D, 0xB8, 0xD8, 0x22  // IP: 93.184.216.34 (but the record type is invalid)
    };
    
    printf("Test: Invalid DNS Record Type\n");
    parse_dns_packet(mock_dns_packet, sizeof(mock_dns_packet));
}

// Test for out-of-bounds data
void test_dns_parsing_out_of_bounds(void) {
    unsigned char mock_dns_packet[] = {
        // Mock DNS Header
        0x00, 0x01,  // ID
        0x81, 0x80,  // Flags
        0x00, 0x01,  // Questions
        0x00, 0x01,  // Answer RRs
        0x00, 0x00,  // Authority RRs
        0x00, 0x00,  // Additional RRs
        // Domain Question (example.com)
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        
        // Incomplete answer data, out of bounds
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01  // Missing actual answer data, causing out-of-bounds read
    };
    
    printf("Test: Out of Bounds Data\n");
    parse_dns_packet(mock_dns_packet, sizeof(mock_dns_packet));
}

// Test for interface listing
void test_list_interfaces(void) {
   char errbuf[PCAP_ERRBUF_SIZE];
   pcap_if_t *interfaces, *temp;
   
   if (pcap_findalldevs(&interfaces, errbuf) == -1) {
       fprintf(stderr, "Error finding devices: %s\n", errbuf);
       return;
   }
    
   // Get the list of all interfaces on the system
  
    getifaddrs (&ifap);
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        //printf("%s, %p\n", ifa->ifa_name, ifa->ifa_addr);
    }

    freeifaddrs(ifap);
}

// Test for logging
void test_log_printf(void) {
    char buffer[1024];
    char expected[1024];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    snprintf(expected, sizeof(expected), "[%04d-%02d-%02d %02d:%02d:%02d]  Test log entry\n",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    log_file = fopen("test_log.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(log_file);
    log_printf(" Test log entry\n");

    fclose(log_file);
    FILE *file = fopen("test_log.txt", "r");
    CU_ASSERT_PTR_NOT_NULL(file);
    fgets(buffer, sizeof(buffer), file);
    fclose(file);

    // Check that log file contains the expected timestamped entry
    CU_ASSERT_STRING_EQUAL(buffer, expected);
}

// Main function to run all test cases
int main() {
    CU_initialize_registry();
    
    CU_pSuite pSuite = CU_add_suite("Network Sniffer Tests", NULL, NULL);
    
    // Add test cases
    CU_add_test(pSuite, "Test Stack Operations", test_stack_operations);
    CU_add_test(pSuite, "Test DNS Parsing", test_dns_parsing);
    CU_add_test(pSuite, "Test DNS Parsing (Truncated)", test_dns_parsing_truncated);
    CU_add_test(pSuite, "Test List Interfaces", test_list_interfaces);
    CU_add_test(pSuite, "Test Log Printing", test_log_printf);
    CU_add_test(pSuite, "Test DNS Parsing (Invalid Header)", test_dns_parsing_invalid_header);
    CU_add_test(pSuite, "Test DNS Parsing (Invalid Domain)", test_dns_parsing_invalid_domain);
    CU_add_test(pSuite, "Test DNS Parsing (Invalid Record Type)", test_dns_parsing_invalid_record_type);
    CU_add_test(pSuite, "Test DNS Parsing (Out of Bounds)", test_dns_parsing_out_of_bounds);
    
    // Run the tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    
    return 0;
}
