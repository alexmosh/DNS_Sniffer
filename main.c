/*
 * File: main.c
 * Description: This file contains the main program for network sniffing, DNS packet parsing,
 *              and unit tests for DNS stack operations and network functionalities.
 *              It integrates with pcap for network interface listing and DNS packet analysis.
 *              The file also includes tests for different DNS scenarios like invalid headers,
 *              truncated packets, and incorrect record types.
 *
 * Author: [Your Name]
 * Date: [Current Date or Creation Date]
 *
 * License: [Your License Type, e.g., MIT, GPL, etc.]
 *
 * Compilation Instructions:
 *   - Compile using a C compiler, linking with required libraries (e.g., pcap, CUnit)
 *   - Example: gcc main.c -o main -lpcap -lcunit
 *
 * Dependencies:
 *   - pcap library (for packet capture and network interface listing)
 *   - CUnit library (for unit testing)
 *   - Standard C libraries (stdio, stdlib, string, time, etc.)
 *
 * Usage:
 *   - Run the program to execute unit tests for DNS parsing, network operations, and logging.
 *   - The program also performs DNS packet parsing and outputs results based on mock DNS data.
 *
 * Change History:
 *   [Date] - Initial version.
 *   [Date] - [Changes made in the file, bug fixes, or added features].
 */

#include "network_sniffer.h"

// Global Variables
char resolved_domains[MAX_DOMAINS][256];  // Array to store resolved domains
int sniffing = 1;  // Flag to control sniffing loop
extern int disable_verification;  // External variable for verification status
FILE *log_file;  // Log file pointer for logging sniffing results
DNSStack stack;  // Stack to manage DNS queries

// Main function - Entry point of the application
int main(int argc, char *argv[]) {
    int choice;  // User's menu choice
    char interface[256] = "";  // Network interface to sniff on
    int sniff_duration = 0;  // Duration for sniffing in seconds
    const char *filename = "config.json";  // Configuration file name
    char *fileContent = readFile(filename);   // Step 1: Read the content of the config file
    cJSON *json = cJSON_Parse(fileContent);    // Step 2: Parse the JSON content

    // If there was an error parsing the JSON file
    if (!json) {
        fprintf(stderr, "Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        free(fileContent);  // Free the memory allocated for file content
        exit(EXIT_FAILURE);  // Exit with failure status
    }

    free(fileContent); // File content no longer needed, so free it

    // Retrieve specific items from the JSON (Network Interface and Sniffing Time)
    cJSON *menu2Item = cJSON_GetObjectItem(json, "NIC");
    cJSON *menu3Item = cJSON_GetObjectItem(json, "Time2Sniff");

    // If NIC (Network Interface) is present and is a string, store it
    if (menu2Item && cJSON_IsString(menu2Item)) {
        strncpy(interface, menu2Item->valuestring, sizeof(interface) - 1);
        interface[sizeof(interface) - 1] = '\0';  // Null-terminate the string
        // for debug printf("Menu #2: %s | %s\n", menu2Item->valuestring, interface);
    }

    // If Time2Sniff is present and is a string, convert it to an integer and store it
    if (menu3Item && cJSON_IsString(menu3Item)) {
        sniff_duration = atoi(menu3Item->valuestring);
        // for debug printf("Menu #3: %s | %d\n", menu3Item->valuestring, sniff_duration);
    }

    // Initialize the DNS stack
    init_stack(&stack);
    log_file = fopen("sniffer.log", "a");  // Open log file in append mode
    if (!log_file) {
        fprintf(stderr, "Error: Unable to open log file\n");
        return 1;  // Exit if unable to open log file
    }

    // Main loop for the Network Sniffer Tool
    while (1) {
        print_banner();  // Print the banner
        printf("\n\nNetwork Sniffer Tool\n");
        printf("----------------------\n");
        printf("1. List Available Interfaces\n");
        printf("2. Select an Interface\n");
        printf("3. Set Sniffing Time Limit (Current: %d sec)\n", sniff_duration);
        printf("4. Enable/Disable Verification (Current: %s)\n", disable_verification ? "Disabled" : "Enabled");
        printf(GREEN_COLOR "5. Start Sniffing on Interface: [ %s ]\n", strlen(interface) > 0 ? interface : "(Current: None selected)");
        printf(RESET_COLOR);
        printf("6. Exit\n");
        printf("Enter choice between 1-6: ");
        scanf("%d", &choice);  // Read user input for menu choice

        // Check if the choice is between 1 and 6
        if (choice >= 1 && choice <= 6) {
            switch (choice) {
                case 1:  // List available network interfaces
                    list_interfaces();
                    break;
                case 2:  // Select a network interface
                    printf("Enter the name of the interface to select: ");
                    scanf("%s", interface);
                    printf("Selected Interface: %s\n", interface);
                    break;
                case 3:  // Set sniffing time limit
                    printf("Enter sniffing duration in seconds: ");
                    scanf("%d", &sniff_duration);
                    break;
                case 4:  // Enable/Disable verification
                    disable_verification = !disable_verification;  // Toggle verification
                    printf("Verification %s.\n", disable_verification ? "disabled" : "enabled");
                    break;
                case 5:  // Start sniffing on the selected interface
                    if (strlen(interface) == 0) {
                        printf("No interface selected. Please set the interface first.\n");
                        break;  // Exit if no interface selected
                    }
                    if (sniff_duration <= 0) {
                        printf("Invalid sniffing duration. Please set the duration first.\n");
                        break;  // Exit if invalid sniffing duration
                    }
                    char errbuf[PCAP_ERRBUF_SIZE];  // Buffer for error messages
                    pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);  // Open the interface for sniffing
                    if (!handle) {
                        fprintf(stderr, "Error opening device: %s\n", errbuf);
                        break;  // Exit if the interface cannot be opened
                    }

                    // Compile and set filter to capture only UDP DNS traffic (port 53)
                    struct bpf_program filter;
                    if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
                        pcap_setfilter(handle, &filter) == -1) {
                        fprintf(stderr, "Error setting filter\n");
                        pcap_close(handle);
                        break;
                    }

                    printf("Sniffing on %s for %d seconds...\n", interface, sniff_duration);
                    signal(SIGINT, stop_sniffing);  // Set signal handler to stop sniffing
                    sniffing = 1;  // Set sniffing flag to true

                    // Start sniffing for the specified duration
                    time_t start_time = time(NULL);
                    while (sniffing && (time(NULL) - start_time) < sniff_duration) {
                        pcap_dispatch(handle, -1, packet_handler, NULL);  // Process packets
                    }

                    printf("Sniffing stopped.\n");
                    pcap_close(handle);  // Close the sniffing handle
                    break;
                case 6:  // Exit the program
                    fclose(log_file);  // Close log file
                    display_stack(&stack);  // Display the DNS stack
                    return 0;  // Exit the program
                default:
                    printf("Invalid choice. Please try again.\n");
            }
        }
    }
    fclose(log_file);  // Close log file if the loop ends (it shouldn't)
    return 0;  // Exit the program
}
