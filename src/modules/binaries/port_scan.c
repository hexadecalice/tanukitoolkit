#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <string.h>
#include <unistd.h>

#define SCAN_TIMEOUT 10

pcap_t *global_pcap_handle = NULL;

void sig_handler(int sig) {
    if (global_pcap_handle != NULL) {
        pcap_breakloop(global_pcap_handle);
    }
}

typedef struct port_info { 
    int dst_port;
    char* target_host;
} port_info;

typedef struct buffer_info { 
    int write_index; 
    int read_index; 
    int b_size;
    port_info* buffer;
} buffer_info; 

typedef struct config { 
    int port_max; 
    char* interface; 
    buffer_info* buffer_struct;
    pthread_mutex_t lock; 
    pthread_cond_t not_empty; 
    pthread_cond_t not_full; 
    atomic_int* packet_count; 
} config;

typedef struct sniffer_context { 
    pcap_t* handle; 
    char* dev_name; 
    int port_max; 
    int* port_count;
} sniffer_context; 

bool queue_empty(buffer_info* buffer) { 
    return (buffer->write_index == buffer->read_index);
}

bool queue_full(buffer_info* buffer) {
    //checks if read index is one ahead of write, if so the queue is full
    return (((buffer->write_index + 1) % buffer->b_size) == buffer->read_index);
}

void* scan_port(void* scan_info) {
    //making some aliases because thisll get ugly quick without it lmao
    config* scan_details = (config*) scan_info;
    char* interface = scan_details->interface;
    int port_max = scan_details->port_max;

    //unique seed to make rand thread safe
    unsigned int random_seed = time(NULL) ^ pthread_self();
    char errbuff[LIBNET_ERRBUF_SIZE];
    atomic_int* packet_count = scan_details->packet_count; 
    buffer_info* buf_info = scan_details->buffer_struct; 

    libnet_t* handle;
    if( (handle = libnet_init(LIBNET_RAW4, interface, errbuff)) == NULL) { 
        printf("[ERROR] Libnet failed to initialize, failed with error %s\n", errbuff); 
        exit(1);
    } 

    while(*packet_count < port_max) { 
        //lock the mutex to check the q 
        pthread_mutex_lock(&scan_details->lock);

        while(queue_empty(buf_info)  && *packet_count != port_max) { 
            pthread_cond_wait(&scan_details->not_empty, &scan_details->lock);
        }

        //this kills the remaining threads that woke up after the scan finishes.
        if(*packet_count == port_max ) { 
            pthread_mutex_unlock(&scan_details->lock);
            break;
        }
        
        //ugly as shit copy the current port to scan off the ring buffer 
        port_info current_port = buf_info->buffer[buf_info->read_index];
        
        //also so ugly but increment read index and wrap if necessary
        buf_info->read_index = (buf_info->read_index + 1) % buf_info->b_size; 
        
        //updates our packet count
        (*scan_details->packet_count)++;

        //let the main thread know it can start pushing things in the buffer again if its asleep
        pthread_cond_signal(&scan_details->not_full);
        pthread_mutex_unlock(&scan_details->lock); 

        //Generate a random emphhehemererelalarall port
        int random_src_port = (rand_r(&random_seed) % (65535 - 49152 + 1)) + 49152;
        int random_seq = (rand_r(&random_seed) % (18000 - 1 + 1)) + 1;


        //dude i am in hell with these function signatures 
        if (libnet_build_tcp(
        random_src_port,       /* source port */
        current_port.dst_port, /* destination port */
        random_seq,            /* sequence number */
        0,                     /* acknowledgement number */
        TH_SYN,                /* control flags */
        1024,                  /* window size */
        0,                     /* checksum (0 for libnet to autofilll) */
        0,                     /* urgent pointer */
        LIBNET_TCP_H,          /* total length of the TCP packet, just the header 4 our packets */
        NULL,                  /* payload */
        0,                     /* payload size */
        handle,                /* libnet context thing */
        0                      /* ptag (0 to build a new one) */
        ) == -1) {
            printf("[ERROR] Failed to build TCP layer with error %s\n", errbuff);
            exit(1);
        }

        uint32_t target_address = inet_addr(current_port.target_host);

        //parameters are size, higher layer protocol, target, and libnet handle
        if(libnet_autobuild_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H, IPPROTO_TCP, target_address, handle) == -1) { 
            printf("[ERROR] Failed to build IPv4 layer with error %s\n", errbuff); 
            exit(1);
        } 

        if(libnet_write(handle) == -1) { 
            printf("Sending SYN packet failed with error %s\n", errbuff);
            exit(1);
        }

        libnet_clear_packet(handle);
    }
    
    //wake up remaining sleeping threads`
    pthread_cond_broadcast(&scan_details->not_empty);
    libnet_destroy(handle);

    return NULL;
}

void capture_packet(u_char *args, const struct pcap_pkthdr *packet_header, const u_char* packet) { 
    //reset the idle timeout clock every time we catch a packet
    alarm(SCAN_TIMEOUT);

    sniffer_context *context = (sniffer_context*) args; 

    //pull the size of the IP header out of the ip header 
    struct ip *ip_header = (struct ip*)(packet + ETHER_HDR_LEN);
    int ip_hdr_len = ip_header->ip_hl * 4; 

    //keep walking up that shit to grab the port and flags 
    struct tcphdr *tcp_header = (struct tcphdr*)(packet + ETHER_HDR_LEN + ip_hdr_len);
    uint16_t source_port = ntohs(tcp_header->th_sport);

    if (tcp_header->th_flags == (TH_SYN | TH_ACK)) {
        printf("OPEN PORT: %u\n", source_port);
    } else if (tcp_header->th_flags & TH_RST) {
        printf("CLOSED PORT: %u\n", source_port);
    }

    (*(context->port_count))++;

    if(*(context->port_count) >= context->port_max) { 
        pcap_breakloop(context->handle);
    }
}

//wrapper function for the loop callback
void* sniffer_thread_func(void* arg) { 
    sniffer_context *context = (sniffer_context*) arg; 
    pcap_loop(context->handle, -1, capture_packet, (u_char*)context);
    return NULL;
}

int main(int argc, char *argv[]) { 
    if(argc < 9) { 
        printf("Not enough arguments! Use tanuki.py -h for a list of commands.\n");
        exit(1);
    }

    //provided arguments
    char* target_hostname = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);
    char* interface = argv[4];
    int thread_max = atoi(argv[5]); 
    int thread_default = atoi(argv[6]); 
    char* target_ip = argv[7];
    char* local_ip = argv[8]; 

    if(thread_max == -1) { 
        thread_max = thread_default;
    }

    //sniffer stuff 
    char pcap_errbuff[PCAP_ERRBUF_SIZE];
    struct bpf_program bpf_struct;
    char* device;
    char bpf_string[256]; 

    //format bpf string
    snprintf(bpf_string, sizeof(bpf_string), "src host %s and dst host %s and (tcp[13] == 18 or tcp[13] == 20 or tcp[13] == 4)", target_ip, local_ip);

    pcap_if_t *interface_list; 

    if(pcap_findalldevs(&interface_list, pcap_errbuff) == -1) { 
        printf("Sorry, locating network interfaces failed with error %s\n", pcap_errbuff);
        exit(1);
    }

    //walk up the ~linked list~ to grab the interface name 
    while(strcmp(interface_list->name, interface) != 0) { 
        if(interface_list->next != NULL) { 
            interface_list = interface_list->next; 
        }
        else { 
            printf("Sorry, couldn't locate specified interface to sniff on.\n");
            exit(1);
        }
    }

    device = strdup(interface_list->name); 
    //this might be a memory leak? i dont know if freealldevs frees the whole thing or just the current value onwards in the list
    //TODO: if it is save the head and free that 
    pcap_freealldevs(interface_list); 

    bpf_u_int32 net_ip;
    bpf_u_int32 netmask; 

    if (pcap_lookupnet(device, &net_ip, &netmask, pcap_errbuff) == -1) { 
        netmask = PCAP_NETMASK_UNKNOWN; 
    }
    
    pcap_t *csession = pcap_open_live(device, BUFSIZ, 1, -1, pcap_errbuff); 
    if(csession == NULL) { 
        printf("Session creation failed with error %s\n", pcap_errbuff);
        exit(4);
    }  

    global_pcap_handle = csession;
    signal(SIGINT, sig_handler);
    signal(SIGALRM, sig_handler);
    
    //set the initial clock so it doesn't hang if zero packets are ever received
    alarm(SCAN_TIMEOUT);

    int ports_scanned = 0;
    sniffer_context sniff_con = { 
        .handle = csession, 
        .dev_name = interface, 
        .port_max = end_port - start_port + 1,
        .port_count = &ports_scanned
    };

    //compile and apply the BPF filter from the formatted string
    if (pcap_compile(csession, &bpf_struct, bpf_string, 0, netmask) == -1) {
        printf("Failed to compile BPF filter: %s\n", pcap_geterr(csession));
        exit(1);
    }
    
    if (pcap_setfilter(csession, &bpf_struct) == -1) {
        printf("Failed to install BPF filter: %s\n", pcap_geterr(csession));
        exit(1);
    }

    pthread_t* thread_id_list = (pthread_t *)malloc(thread_max * sizeof(pthread_t));
    if (thread_id_list == NULL) {
        exit(1);
    }

    atomic_int p_count = 0; 
    
    //allocate room for our buffer on the heap
    port_info* port_list = (port_info *)malloc((end_port - start_port + 1)* sizeof(port_info));
    if (port_list == NULL) {
        exit(1);
    }

    buffer_info buffer_struct = { 
        .read_index = 0,
        .write_index = 0,
        .b_size = end_port - start_port + 1,
        .buffer = port_list
    };

    config config_struct = { 
        .port_max = end_port - start_port + 1,
        .interface = interface,
        .buffer_struct = &buffer_struct,
        .lock = PTHREAD_MUTEX_INITIALIZER, 
        .not_empty = PTHREAD_COND_INITIALIZER, 
        .not_full = PTHREAD_COND_INITIALIZER, 
        .packet_count = &p_count
    };

    for(int i = 0; i < thread_max; i++) { 
        pthread_create(&thread_id_list[i], NULL, scan_port, (void*) &config_struct); 
    }

    pthread_t sniffer_thread_id; 
    pthread_create(&sniffer_thread_id, NULL, sniffer_thread_func, (void*)&sniff_con);

    int* write_index = &config_struct.buffer_struct->write_index; 

    for(int port = start_port; port <= end_port; port++) { 
        port_info current_port = { 
            .dst_port = port,
            .target_host = target_ip
        };

        pthread_mutex_lock(&config_struct.lock);
        while(queue_full(config_struct.buffer_struct)) {
            pthread_cond_wait(&config_struct.not_full, &config_struct.lock); 
        }

        config_struct.buffer_struct->buffer[*write_index] = current_port;
        
        //increase and wrap around if needed
        //jesus this is so fucking ugly. 
        *write_index = (*write_index + 1) % config_struct.buffer_struct->b_size;

        pthread_cond_signal(&config_struct.not_empty); 
        pthread_mutex_unlock(&config_struct.lock); 
    } 

    for(int i = 0; i < thread_max; i++) { 
        pthread_join(thread_id_list[i], NULL); 
    }

    pthread_join(sniffer_thread_id, NULL);

    free(port_list);
    free(thread_id_list);
    return 0;
}