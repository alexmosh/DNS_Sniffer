// File: utils.c
// Description: Utility functions for logging and stack operations.

#include "network_sniffer.h"

FILE *log_file;


// Function to read the content of a file into a string
char *readFile(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(length + 1);
    if (!content) {
        perror("Memory allocation error");
        exit(EXIT_FAILURE);
    }

    fread(content, 1, length, file);
    content[length] = '\0';

    fclose(file);
    return content;
}

// Function to write a string to a file
void writeFile(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }

    fprintf(file, "%s", content);
    fclose(file);
}


void log_printf(const char *format, ...) {
    time_t now = time(NULL);
    struct tm *local_time = localtime(&now);
    fprintf(log_file, "[%02d-%02d-%02d %02d:%02d:%02d] ", 
            local_time->tm_year + 1900, local_time->tm_mon + 1, local_time->tm_mday,
            local_time->tm_hour, local_time->tm_min, local_time->tm_sec);

    va_list args;
    va_start(args, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    fprintf(log_file, "%s\n", buffer);  // Ensure new line after each log entry
    fflush(log_file);
    // Print to console (stdout)
    vprintf(format, args);
    va_end(args);
}


void init_stack(DNSStack *s) {
    s->top = -1;
}

int is_empty(DNSStack *s) {
    return s->top == -1;
}

int is_full(DNSStack *s) {
    return s->top == MAX_DOMAINS - 1;
}

void push(DNSStack *s, const char *domain, const char *ipv4, const char *ipv6, const char *cname) {
    if (!is_full(s)) {
        s->top++;
        strncpy(s->stack[s->top].domain_name, domain, sizeof(s->stack[s->top].domain_name));
        strncpy(s->stack[s->top].resolved_ipv4, ipv4, sizeof(s->stack[s->top].resolved_ipv4));
        strncpy(s->stack[s->top].resolved_ipv6, ipv6, sizeof(s->stack[s->top].resolved_ipv6));
        strncpy(s->stack[s->top].cname_record, cname, sizeof(s->stack[s->top].cname_record));
    }
}

int pop(DNSStack *s, DNSRecord *record) {
    if (!is_empty(s)) {
        *record = s->stack[s->top--];
        return 1;
    }
    return 0;
}

int peek(DNSStack *s, DNSRecord *record) {
    if (!is_empty(s)) {
        *record = s->stack[s->top];
        return 1;
    }
    return 0;
}

void display_stack(DNSStack *s) {
    if (is_empty(s)) {
        printf("Stack is empty\n");
        return;
    }

   // Print the header of the table
printf("+------------------------------------------------------------+-------------------------+------------------------------------------------------------+-------------------------+\n");
printf("| %-60s | %-23s | %-60s | %-23s |\n", "Domain Name", "Resolved IPv4", "Resolved IPv6", "CNAME Record");
printf("+------------------------------------------------------------+-------------------------+------------------------------------------------------------+-------------------------+\n");

// Iterate through the stack and print each record in the table format
for (int i = 0; i <= s->top; i++) {
    printf("| %-60s | %-23s | %-60s | %-23s |\n", 
        s->stack[i].domain_name,
        s->stack[i].resolved_ipv4, 
        s->stack[i].resolved_ipv6, 
        s->stack[i].cname_record);
}

printf("+------------------------------------------------------------+-------------------------+------------------------------------------------------------+-------------------------+\n");
}
