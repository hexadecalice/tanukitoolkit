#include <stdio.h>
#include <pcap.h>
#include <libnet.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>

typedef struct port_info { 
	int src_port;
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


bool queue_empty(buffer_info* buffer) { 
	if(buffer->write_index == buffer->read_index) { 
		return true;
	}
	else { 
		return false;
	}

}

bool queue_full(buffer_info* buffer) {

	//checks if read index is one ahead of write, if so the queue is full
	if(((buffer->write_index + 1) % buffer->b_size) == read_index) { 
		return true; 
	}
	else { 
		return false;
	}

}

void* scan_port(void* scan_details) {

	//making some aliases because thisll get ugly quick without it lmao
	config* scan_details = (config*) scan_details;
	char* interface = scan_details->interface;
	int port_max = scan_details->port_max;
	char errbuff[LIBNET_ERRBUF_SIZE];
	atomic_int* packet_count = scan_details->packet_count; 
	buffer_info* buffer_info = scan_details->buffer_struct; 




	libnet_t* handle;
	if( (handle = libnet_init(LIBNET_RAW4, interface, errbuff)) == NULL) { 
		printf("[ERROR] Libnet failed to initialize, failed with error %s", errbuff); 
	} 

	while(*packet_count < port_max) { 
		//lock the mutex to check the q 
		pthread_mutex_lock(&scan_details->lock);
		while(queue_empty(buffer_info)) { 
			pthread_cond_wait(&scan_details->not_empty, &scan_details->lock);
		}
		//copy the current port to scan off the ring buffer 
		port_info current_port = buffer_info->buffer[read_index];

		//ugly as shit but we increment the read index and wrap it if necessary 
		buffer_info->read_index = (buffer_info->read_index + 1) % buffer_info->b_size; 

		pthread_mutex_unlock(&scan_details->lock); 

		

		
	}




}

int main(int argc, char *argv[]) { 

	if(argc < 7) { 

		printf("Not enough arguments! Use tanuki.py -h for a list of commands.");

	}

	char* target_hostname = argv[1];
	int start_port = atoi(argv[2]);
	int end_port = atoi(argv[3]);
	char* interface = argv[4];
	int thread_max = atoi(argv[5]); 
	int default_thread = atoi(argv[6]); 

	if(thread_max == -1) { 
		thread_max = default_thread; 
	}

	char error_buffer[LIBNET_ERRBUF_SIZE];







}