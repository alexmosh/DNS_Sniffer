// File: main.c
// Description: Entry point and main logic of the Network Sniffer tool.

#include "network_sniffer.h"

// Global Variables
char resolved_domains[MAX_DOMAINS][256];
int sniffing = 1;
extern int disable_verification;
FILE *log_file;
DNSStack stack;

int main(int argc, char *argv[]) {
    int choice;
    char interface[256] = "";
    int sniff_duration = 0;
    const char *filename = "config.json";
    char *fileContent = readFile(filename);   // Step 1: Read JSON file
   cJSON *json = cJSON_Parse(fileContent);    // Step 2: Parse JSON content

    if (!json) {
        fprintf(stderr, "Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        free(fileContent);
        exit(EXIT_FAILURE);
    }

    free(fileContent); // File content no longer needed

    cJSON *menu2Item = cJSON_GetObjectItem(json, "NIC");
    cJSON *menu3Item = cJSON_GetObjectItem(json, "Time2Sniff");

    if (menu2Item && cJSON_IsString(menu2Item)) {
        strncpy(interface, menu2Item->valuestring, sizeof(interface) - 1);
        interface[sizeof(interface) - 1] = '\0'; // Null-terminate the string
        printf("Menu #2: %s | %s\n", menu2Item->valuestring, interface);
    }

    if (menu3Item && cJSON_IsString(menu3Item)) {
        sniff_duration = atoi(menu3Item->valuestring);
        printf("Menu #3: %s | %d\n", menu3Item->valuestring,sniff_duration);
    }

    init_stack(&stack);
    log_file = fopen("sniffer.log", "a");
    if (!log_file) {
        fprintf(stderr, "Error: Unable to open log file\n");
        return 1;
    }

    while (1) {
        printf("\n\nNetwork Sniffer Tool\n");
        printf("----------------------\n");
        printf("1. List Available Interfaces\n");
        printf("2. Select an Interface\n");
        printf("3. Set Sniffing Time Limit (Current: %d sec)\n", sniff_duration);
        printf("4. Enable/Disable Verification (Current: %s)\n", disable_verification ? "Disabled" : "Enabled");          // Highlight the "Enable/Disable Verification" option in green
        printf(GREEN_COLOR "5. Start Sniffing on Interface: [ %s ]\n", strlen(interface) > 0 ? interface : "(Current: None selected)");
        printf(RESET_COLOR);
        printf("6. Exit\n");
        printf("Enter choice between 1-6:");
        scanf("%d", &choice);
        if (choice >= 1 && choice <= 6)
        {
        switch (choice) {
            case 1:
                list_interfaces();
                break;
            case 2:
                printf("Enter the name of the interface to select: ");
                scanf("%s", interface);
                printf("Selected Interface: %s\n", interface);
                break;
            case 3:
                printf("Enter sniffing duration in seconds: ");
                scanf("%d", &sniff_duration);
                break;
            case 4:
                disable_verification = !disable_verification;
                printf("Verification %s.\n", disable_verification ? "disabled" : "enabled");
                break;
            case 5:
                if (strlen(interface) == 0) {
                    printf("No interface selected. Please set the interface first.\n");
                    break;
                }
                if (sniff_duration <= 0) {
                    printf("Invalid sniffing duration. Please set the duration first.\n");
                    break;
                }
                char errbuf[PCAP_ERRBUF_SIZE];
                pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
                if (!handle) {
                    fprintf(stderr, "Error opening device: %s\n", errbuf);
                    break;
                }

                struct bpf_program filter;
                if (pcap_compile(handle, &filter, "udp port 53", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
                    pcap_setfilter(handle, &filter) == -1) {
                    fprintf(stderr, "Error setting filter\n");
                    pcap_close(handle);
                    break;
                }

                printf("Sniffing on %s for %d seconds...\n", interface, sniff_duration);
                signal(SIGINT, stop_sniffing);
                sniffing = 1;

                time_t start_time = time(NULL);
                while (sniffing && (time(NULL) - start_time) < sniff_duration) {
                    pcap_dispatch(handle, -1, packet_handler, NULL);
                }

                printf("Sniffing stopped.\n");
                pcap_close(handle);
                break;
            case 6:
                fclose(log_file);
                display_stack(&stack);
                return 0;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
}
    fclose(log_file);
    return 0;
}
