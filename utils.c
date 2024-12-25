/*
 * File: utils.c
 * Description: This file contains utility functions that support various operations in the 
 *              network sniffer application. Functions include helper utilities for string 
 *              manipulation, memory management, logging, and other common tasks that assist 
 *              in handling network data or interacting with the system.
 *
 * Author: [Your Name]
 * Date: [Current Date or Creation Date]
 *
 * License: [Your License Type, e.g., MIT, GPL, etc.]
 *
 * Compilation Instructions:
 *   - Compile using a C compiler, linking with any required libraries
 *   - Example: gcc utils.c -o utils
 *
 * Dependencies:
 *   - Standard C libraries (stdio, stdlib, string, etc.)
 *   - [Any additional external libraries if used]
 *
 * Usage:
 *   - This file provides utility functions for the network sniffer, such as memory allocation 
 *     handling, string formatting, and logging. The functions can be reused across different 
 *     modules in the application to avoid redundant code.
 *
 * Change History:
 *   [Date] - Initial version.
 *   [Date] - [Changes made in the file, bug fixes, or added features].
 */


#include "network_sniffer.h"

FILE *log_file;  // File pointer for the log file

// Function to read the content of a file into a string
char *readFile(const char *filename) {
    FILE *file = fopen(filename, "r");  // Open file in read mode
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);  // Exit if file cannot be opened
    }
    fseek(file, 0, SEEK_END);  // Move to the end of the file
    long length = ftell(file);  // Get the file length
    fseek(file, 0, SEEK_SET);  // Reset file pointer to the beginning
    char *content = malloc(length + 1);  // Allocate memory to store the content
    if (!content) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);  // Exit if memory allocation fails
    }
    fread(content, 1, length, file);  // Read file content into memory
    content[length] = '\0';  // Null-terminate the string
    fclose(file);  // Close the file
    return content;  // Return the content
}

// Function to write a string to a file
void writeFile(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");  // Open file in write mode
    if (!file) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);  // Exit if file cannot be opened
    }
    fprintf(file, "%s", content);  // Write the content to the file
    fclose(file);  // Close the file
}

// Function to log messages with a timestamp
void log_printf(const char *format, ...) {
    time_t now = time(NULL);  // Get current time
    struct tm *local_time = localtime(&now);  // Convert time to local time
    // Print timestamp to log file
    fprintf(log_file, "[%02d-%02d-%02d %02d:%02d:%02d] ", 
            local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec);
    
    va_list args;
    va_start(args, format);  // Initialize the variable arguments
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);  // Format the log message
    va_end(args);
    
    fprintf(log_file, "%s\n", buffer);  // Write the formatted message to the log file
    fflush(log_file);  // Ensure the log message is written immediately
    // Print the message to the console (stdout)
    vprintf(format, args);
    va_end(args);
}

// Function to initialize the stack (set the top to -1)
void init_stack(DNSStack *s) {
    s->top = -1;
}

// Function to check if the stack is empty (top is -1)
int is_empty(DNSStack *s) {
    return s->top == -1;
}

// Function to check if the stack is full (top is at MAX_DOMAINS - 1)
int is_full(DNSStack *s) {
    return s->top == MAX_DOMAINS - 1;
}

// Function to push a new DNS record onto the stack
void push(DNSStack *s, const char *domain, const char *ipv4, const char *ipv6, const char *cname) {
    if (!is_full(s)) {  // Ensure stack is not full
        s->top++;  // Move the top pointer
        // Copy the domain and address data into the stack's current position
        strncpy(s->stack[s->top].domain_name, domain, sizeof(s->stack[s->top].domain_name));
        strncpy(s->stack[s->top].resolved_ipv4, ipv4, sizeof(s->stack[s->top].resolved_ipv4));
        strncpy(s->stack[s->top].resolved_ipv6, ipv6, sizeof(s->stack[s->top].resolved_ipv6));
        strncpy(s->stack[s->top].cname_record, cname, sizeof(s->stack[s->top].cname_record));
    }
}

// Function to pop a DNS record from the stack
int pop(DNSStack *s, DNSRecord *record) {
    if (!is_empty(s)) {  // Ensure stack is not empty
        *record = s->stack[s->top--];  // Copy the top record and move the top pointer down
        return 1;  // Indicate success
    }
    return 0;  // Indicate failure (stack was empty)
}

// Function to display a banner for the program
void print_banner() {
    // Print program banner (ASCII art and information)
    printf("===============================================\n");
    printf("      SSSSS   AAAAA   M     M    \n");
    printf("     S        A   A   MM   MM    \n");
    printf("     SSSSS    AAAAA   M M M M    \n");
    printf("         S    A   A   M  M  M    \n");
    printf("     SSSSS    A   A   M     M    \n");
    printf("===============================================\n");
    printf("       DNS Sniffer - Monitoring Traffic       \n");
    printf("===============================================\n\n");
}

// Function to display the stack of DNS records in a table format
void display_stack(DNSStack *s) {
    if (is_empty(s)) {  // Check if the stack is empty
        printf("Stack is empty\n");
        return;  // Exit if the stack is empty
    }

    // Print the header of the table with column names
    printf("+------------------------------------------------------------+-------------------------+------------------------------------------------------------+-------------------------+\n");
    printf("| %-60s | %-23s | %-60s | %-23s |\n", "Domain Name", "Resolved IPv4", "Resolved IPv6", "CNAME Record");
    printf("+------------------------------------------------------------+-------------------------+------------------------------------------------------------+-------------------------+\n");

    // Iterate through the stack and print each DNS record in the table format
    for (int i = 0; i <= s->top; i++) {
        printf("| %-60s | %-23s | %-60s | %-23s |\n", 
            s->stack[i].domain_name,  // Print domain name
            s->stack[i].resolved_ipv4,  // Print resolved IPv4 address
            s->stack[i].resolved_ipv6,  // Print resolved IPv6 address
            s->stack[i].cname_record);  // Print CNAME record
    }
    printf("+------------------------------------------------------------+-------------------------+------------------------------------------------------------+-------------------------+\n");
}
