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
	if(((buffer->write_index + 1) % buffer->b_size) == buffer->read_index) { 
		return true; 
	}
	else { 
		return false;
	}

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
	buffer_info* buffer_info = scan_details->buffer_struct; 




	libnet_t* handle;
	if( (handle = libnet_init(LIBNET_RAW4, interface, errbuff)) == NULL) { 
		printf("[ERROR] Libnet failed to initialize, failed with error %s", errbuff); 
		exit(1);
	} 

	while(*packet_count < port_max) { 
		//lock the mutex to check the q 
		pthread_mutex_lock(&scan_details->lock);

		while(queue_empty(buffer_info)  && *packet_count != port_max) { 
			pthread_cond_wait(&scan_details->not_empty, &scan_details->lock);
		}

		//this kills the remaining threads that woke up after the scan finishes.
		if(*packet_count == port_max ) { 
			pthread_mutex_unlock(&scan_details->lock);
			break;
		}
		//ugly as shit copy the current port to scan off the ring buffer 
		port_info current_port = buffer_info->buffer[buffer_info->read_index];

		//also so ugly but increment read index and wrap if necessary
		buffer_info->read_index = (buffer_info->read_index + 1) % buffer_info->b_size; 

		//updates our packet count
		(*scan_details->packet_count)++;

		//let the main thread know it can start pushing things in the buffer again if its asleep
		pthread_cond_signal(&scan_details->not_full);

		pthread_mutex_unlock(&scan_details->lock); 

		//Generate a random emphhehemererelalarall port
		int random_src_port = (rand_r(&random_seed) % (65535 - 49152 + 1)) + 49152;
		int random_seq = (rand_r(&random_seed) % (18000 - 1 + 1)) + 1;

		//started to write out a reminder for what each part of this function signature does, but it took up like four lines
		//just look it up in the docs if you wanna know lmao
		if(libnet_build_tcp(random_src_port, current_port.dst_port, random_seq, 0, TH_SYN, 1024, 0, 0, LIBNET_TCP_H, NULL, 0, handle, 0) == -1) {
			printf("[ERROR] Failed to build TCP layer with error %s", errbuff);
			exit(1);
		}

		uint32_t target_address = inet_addr(current_port.target_host);

		//parameters are size, higher layer protocol, target, and libnet handle
		if(libnet_autobuild_ipv4(LIBNET_IPV4_H+LIBNET_TCP_H, IPPROTO_TCP,target_address, handle) == -1) { 
			printf("[ERROR] Failed to build IPv4 layer with error %s", errbuff); 
			exit(1);
		} 

		if(libnet_write(handle) == -1) { 
			printf("Sending SYN packet failed with error %s", errbuff);
			exit(1);
		}

		libnet_clear_packet(handle);

		
	}
	libnet_destroy(handle);



	return NULL;
}

int main(int argc, char *argv[]) { 

	if(argc < 8) { 

		printf("Not enough arguments! Use tanuki.py -h for a list of commands.");
		exit(1);

	}

	char* target_hostname = argv[1];
	int start_port = atoi(argv[2]);
	int end_port = atoi(argv[3]);
	char* interface = argv[4];
	int thread_max = atoi(argv[5]); 
	int default_thread = atoi(argv[6]); 
	char* target_ip = argv[7];

	pthread_mutex_t mutex_lock = PTHREAD_MUTEX_INTIALIZER; 
	pthread_cond_t queue_full_c = PTHREAD_COND_INTIALIZER; 
	pthread_cond_t queue_empty_c = PTHREAD_COND_INTIALIZER; 

	atomic_int p_count = 0; 
	

	//allocate room for our buffer on the heap
	port_info* port_list = (port_info *)malloc((end_port - start_port + 1)* sizeof(port_info));


	buffer_info buffer_struct { 
		.read_index = 0,
		.write_index = 0,
		.buffer = &port_list

	};

	config config_struct = { 
		.port_max = end_port,
		.interface = interface,
		.buffer_struct = &buffer_struct,
		.lock = mutex_lock, 
		.not_empty = queue_empty_c, 
		.not_full = queue_full_c, 
		.packet_count = &p_count

	};






	if(thread_max == -1) { 
		thread_max = default_thread; 
	}

	char error_buffer[LIBNET_ERRBUF_SIZE];






	free(port_list);
	return 0;
}