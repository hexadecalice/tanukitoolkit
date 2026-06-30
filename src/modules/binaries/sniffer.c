#include <stdlib.h>
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <stdbool.h>





void write_packet(u_char *args, struct pcap_pkthdr *packet_header, const u_char * packet) { 

		pcap_dump(args, packet_header, packet);


}

bool check_file(const char *filename) { 
	FILE *file = fopen(filename, "r"); 
	if (file != NULL) { 
		fclose(file);
		return true; 
	}
	else { 
		return false;
	}

}


int main(void) { 
	
	char *device; 
    pcap_t* csession;

    struct pcap_pkthdr hdr; 
    const u_char *packet;
     char errbuf[PCAP_ERRBUF_SIZE];

    char* filename = "test.pcap\0";
    pcap_dumper_t *file_handle;

    device = pcap_lookupdev(errbuf);



    if(device == NULL){ 
  		printf("Device lookup failed with error %s", errbuf);
  		exit(2);
    }


    csession = pcap_open_live(device, BUFSIZ, 1, -1, errbuf);
    pcap_exists = check_file(filename);

    file_handle = pcap_dump_open(cession, filename);
  

    pcap_loop(csession, -1, (pcap_handler) write_packet, (u_char*) file_handle);

	return 0;	
}