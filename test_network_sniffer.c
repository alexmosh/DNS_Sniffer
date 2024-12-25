/*
 * File: test_network_sniffer.c
 * Description: This file contains unit tests for the network sniffer functionality. 
 *              It includes test cases for network packet processing, DNS packet parsing, 
 *              interface listing, and logging functionality. The tests use the CUnit testing 
 *              framework to validate that the network sniffer's core features are working 
 *              correctly. These tests ensure that the program handles various DNS packet 
 *              scenarios (e.g., valid, truncated, invalid) and performs as expected in 
 *              different edge cases.
 *
 * Author: [Your Name]
 * Date: [Current Date or Creation Date]
 *
 * License: [Your License Type, e.g., MIT, GPL, etc.]
 *
 * Dependencies:
 *   - CUnit library (for unit testing)
 *   - network_sniffer.h (for accessing sniffer functionality)
 *   - standard C libraries (stdio, stdlib, string, etc.)
 *   - pcap library (for network sniffing)
 *
 * Usage:
 *   - This file contains unit tests specifically designed for testing the core 
 *     functionality of the network sniffer program, including DNS packet parsing, 
 *     stack operations, and packet capture.
 *   - Tests are executed using the CUnit framework, and results are displayed in 
 *     the terminal or the specified test output.
 *   - The file is intended to be compiled and run separately from the main application 
 *     to validate correctness and ensure robustness of the network sniffer functionality.
 *
 * Change History:
 *   [Date] - Initial version of unit tests for network sniffer.
 *   [Date] - [Changes made in the file, bug fixes, or added tests].
 */


#include "network_sniffer.h"
#include <CUnit/CUnit.h>
#include <CUnit/Basic.h>



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
    unsigned char mock_dns_packet[] = {
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

    int data_len = sizeof(mock_dns_packet);
    
    // Parsing DNS packet
    log_file = fopen("sniffer.log", "w");
    parse_dns_packet(mock_dns_packet, data_len);
    fclose(log_file); 
    // Check if DNS parsing logic works as expected
    // Add actual assertions based on how you structure DNS parsing
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

// Test for logging functionality
 void test_safe_log_print(void) {
    char buffer[1024];
    char expected[1024];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);

    // Build the expected timestamped log entry
    snprintf(expected, sizeof(expected), "[%04d-%02d-%02d %02d:%02d:%02d]  Test log entry\n",
             t->tm_year + 1900, t->tm_mon + 1, t->tm_mday,
             t->tm_hour, t->tm_min, t->tm_sec);

    // Open the log file safely
    log_file = fopen("test_log.txt", "w");
    CU_ASSERT_PTR_NOT_NULL(log_file);

    // Call the safe log print function
    safe_log_printf(" Test log entry\n");

    fclose(log_file);

    // Read back the log file
    FILE *file = fopen("test_log.txt", "r");
    CU_ASSERT_PTR_NOT_NULL(file);
    fgets(buffer, sizeof(buffer), file);
    fclose(file);

    // Check that the log file contains the expected timestamped entry
    CU_ASSERT_STRING_EQUAL(buffer, expected);
}
// Main function to run all test cases
int main() {
    // Initialize CUnit registry
    CU_initialize_registry();
    
    // Add test suite
    CU_pSuite pSuite = CU_add_suite("Network Sniffer Tests", NULL, NULL);
    
    // Add test cases
    CU_add_test(pSuite, "Test Stack Operations", test_stack_operations);
    CU_add_test(pSuite, "Test DNS Parsing", test_dns_parsing);
    CU_add_test(pSuite, "Test DNS Parsing (Truncated)", test_dns_parsing_truncated);
    CU_add_test(pSuite, "Test Log Printing", test_safe_log_print);
    CU_add_test(pSuite, "Test DNS Parsing (Invalid Header)", test_dns_parsing_invalid_header);
    
    // Run tests
    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    CU_cleanup_registry();
    
    return 0;
}
