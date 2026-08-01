#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>

//big thanks to the people over at stanford for this amazing guide: 
//https://yuba.stanford.edu/~casado/pcap/section1.html
//helped me bridge the gap in record time

volatile sig_atomic_t keep_running = 1;
pcap_t* csession;

void handle_sigint(int sig) {
    //shut up compiler 
    (void)sig;

    pcap_breakloop(csession); 
}

typedef struct { 
    pcap_dumper_t *file_handle; 
    int *packet_count; 
    pcap_t* device_session;
} Configuration;

void write_packet(u_char *args, struct pcap_pkthdr *packet_header, const u_char * packet) { 
    //Recast the u_char pointer to a config struct 
    Configuration* config_file = (Configuration *) args; 

    //Write to pcap and increment packet count
    pcap_dump((u_char*)config_file->file_handle, packet_header, packet);
    (*config_file->packet_count)++;
}

int main(int argc, char *argv[]) { 
    
    if(argc < 3) { 
        printf("[ERROR] Not enough arguments!");
        exit(1);
    }
    //parsing arguments from python wrapper
    char* bpf_string = argv[1]; 
    char* interface_name = argv[2];
    
    char *device; 
    pcap_if_t *network_devices; 

    struct pcap_pkthdr hdr; 
    const u_char *packet;
    char errbuff[PCAP_ERRBUF_SIZE];

    struct bpf_program bpf_struct;
    pcap_dumper_t *file_handle;

    int packet_count = 0;
    int *count_pointer = &packet_count; 

    signal(SIGINT, handle_sigint);

    //get a list of interfaces
    if(pcap_findalldevs(&network_devices, errbuff) == -1) { 
        printf("Device lookup failed with error: %s", errbuff);
        exit(1);
    }

    //copy first interface name from the linked list if not specified
    //if specified, look for that shit
    pcap_if_t* head = network_devices;
    if(interface_name != NULL) { 

        while(strcmp(interface_name, network_devices->name) != 0) {
            if(network_devices->next != NULL) {  
                network_devices = network_devices->next;
            }
            else{
                printf("Sorry, unable to locate interface. Please check your spelling and try again."); 
                exit(2);
            }

        }
    } 
    device = strdup(network_devices->name);

    pcap_freealldevs(head);
    //These hold the data returned by lookupnet()
    bpf_u_int32 net_ip;
    bpf_u_int32 netmask; 

    if (pcap_lookupnet(device, &net_ip, &netmask, errbuff) == -1) { 
        printf("Couldn't resolve netmask, failed with error %s\n", errbuff); 
        netmask = PCAP_NETMASK_UNKNOWN; // Fallback if lookup fails
    }
    
    csession = pcap_open_live(device, BUFSIZ, 1, -1, errbuff);

    if(csession == NULL) { 
        printf("Session creation failed with error %s", errbuff);
        exit(4);
    }  

    //Compile and apply the BPF filter from standard input
    if (pcap_compile(csession, &bpf_struct, bpf_string, 0, netmask) == 0) {
        pcap_setfilter(csession, &bpf_struct);
    }
    
    int fileCount = 0;
    bool fileExists = 1;
    char* filename = "capture";
    char newFile[256]; 

    //Write first attempt at file name to buffer
    snprintf(newFile, sizeof(newFile), "%s-%d.pcap", filename, fileCount);

    while(fileExists) { 
        //Tries to open file, if it already exists overwrite buffer w/ new name
        FILE * pcap_file = fopen(newFile, "r");
        if(pcap_file != NULL) { 
            fileCount++; 
            snprintf(newFile, sizeof(newFile), "%s-%d.pcap", filename, fileCount); 
            fclose(pcap_file);
            
        } else { 
            fileExists = 0; 
        }
    }

    file_handle = pcap_dump_open(csession, newFile);

    Configuration config = { 
        .file_handle = file_handle, 
        .packet_count = count_pointer,
        .device_session = csession, 
    };  
  
    //this is annoying but it helps me remember
    //loop arguments are session handle, time to loop, loopback function, and user variables
    pcap_loop(csession, -1, (pcap_handler) write_packet, (u_char*) &config);
    pcap_dump_close(config.file_handle);
    free(device);

    printf("\nPackets Captured: %i on interface %s \n", packet_count, interface_name);

    return 0;   
}