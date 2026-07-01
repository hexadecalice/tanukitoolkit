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
    pcap_breakloop(csession); 


}

typedef struct { 

    pcap_dumper_t *file_handle; 
    int *packet_count; 
    pcap_t* device_session;


}Configuration;

void write_packet(u_char *args, struct pcap_pkthdr *packet_header, const u_char * packet) { 
        Configuration* config_file = (Configuration *) args; 
        pcap_dump((u_char*)config_file->file_handle, packet_header, packet);
        (*config_file->packet_count)++;

}



int main(void) { 
    
    char *device; 
    pcap_if_t *network_devices; 


    struct pcap_pkthdr hdr; 
    const u_char *packet;
    char errbuff[PCAP_ERRBUF_SIZE];

    char* filename = "test.pcap\0";
    pcap_dumper_t *file_handle;

    int packet_count = 0;
    int *count_pointer = &packet_count; 

    signal(SIGINT, handle_sigint);


   

    
    pcap_findalldevs(&network_devices, errbuff);
    if(network_devices == NULL) { 
        printf("Device lookup failed with error: %s", errbuff);
        exit(1);

    }
    //copy our device name from the linked list 
    device = strdup(network_devices->name);

    pcap_freealldevs(network_devices);

    


    csession = pcap_open_live(device, BUFSIZ, 1, -1, errbuff);


    file_handle = pcap_dump_open(csession, filename);

     Configuration config = { 
        .file_handle = file_handle, 
        .packet_count = count_pointer,
        .device_session = csession, 
    };  
  

    pcap_loop(csession, -1, (pcap_handler) write_packet, (u_char*) &config);

    free(device);

    printf("Packets Captured: %i\n", packet_count);

    return 0;   
}
    