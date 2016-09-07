#include "manyclient.h"

int main(int argc, char * argv[]){
    
	/***************  SEND PACKET  ***************/
	// Random wait to stagger clients
	srand (time(NULL));
	int stagger = rand() % 360000;
	usleep(stagger);

	// For socket address out
    struct addrinfo hints, *server_info, *top_server; 
    memset(&hints, 0, sizeof(hints));       
    hints.ai_family = AF_UNSPEC;         
    hints.ai_socktype = SOCK_DGRAM;  
    // Socket file descriptor and error return holder 
    int sockfd, err;    
	// SNTP data packet to send
    unsigned char sntp_packet[PACKETSIZE] = { 0 }; // Packet to send
    struct timeval transmit_time; // Hold transmit time 
	// Packet in
    unsigned char buffer[PACKETSIZE];  
    struct NTPPacket recv_packet; 
	// Socket address in
    struct sockaddr_in recv_addr;
    socklen_t addr_len = sizeof(recv_addr);
    // Holds all received SNTP server details
    struct manycastDetails servers[11] = {{0}};


    // Resolve hostname/IP address and port to network format.   
    if ((err = getaddrinfo("224.0.1.1", "5001", &hints, &server_info)) != 0){
        fprintf(stderr, "Error - getaddrinfo: %s\n", gai_strerror(err));
        exit(1);
    }
    
    // Create socket
    if ((sockfd = socket(server_info->ai_family, server_info->ai_socktype, server_info->ai_protocol)) == -1){
        perror("Error creating socket");
        exit(1);
    }
    
    // Enable broadcasting and response timeout of 400ms
    int broadcast_enable = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));
	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 400000;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // Build packet
    build_packet(sntp_packet, &transmit_time);
    
    // Send packet to broadcast address
    if (sendto(sockfd, sntp_packet, sizeof(sntp_packet), 0,
    server_info->ai_addr, server_info->ai_addrlen) == -1){
        perror("Error sending packet");
        exit(1);
    }

    /***************  RECEIVE PACKET(S)  ***************/
	// Listen for response(s)
    while(1)
    {
		/********  BROADCAST  ********/
		// Receive packet
		ssize_t count = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &addr_len);
		if (count == -1){
			break;
		} else if (count != sizeof(buffer)){ 
			// Check packet is correct size
			fprintf(stderr, "Error: packet does not match expected size.\n");
		} else {
			// Passed initial checks, convert to struct
			packet_to_struct(&recv_packet, buffer);
			// More sanity checks as per RFC4330 recommendations
			if (verify_packet(&recv_packet, &transmit_time) == 1){
				// Skip packet if failed checks
				continue;
			}
			// All checks passed, add server to array
			add_server_details(&recv_packet, servers, &recv_addr);
			print_server_details(servers);
		}
    }
	
	/********  REQUEST FROM BEST SERVER  ********/
	// Resolve hostname/IP address and port to network format.   
	if ((err = getaddrinfo(inet_ntoa(servers[0].ad), "5001", &hints, &top_server)) != 0){
		fprintf(stderr, "Error - getaddrinfo: %s\n", gai_strerror(err));
		exit(1);
	}
		
	// Create socket
	if ((sockfd = socket(top_server->ai_family, top_server->ai_socktype, top_server->ai_protocol)) == -1){
		perror("Error creating socket");
		exit(1);
	}

	// Build packet
	build_packet(sntp_packet, &transmit_time);
	
	// Send packet
	if (sendto(sockfd, sntp_packet, sizeof(sntp_packet), 0,
	top_server->ai_addr, top_server->ai_addrlen) == -1){
		perror("Error sending packet");
		exit(1);
	}
	
	// Receive packet
	ssize_t count = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&recv_addr, &addr_len);
	if (count == -1){
		fprintf(stderr, "recvfrom error: \n");
		return 1;
	} else if(inet_ntoa(recv_addr.sin_addr) != inet_ntoa(((struct sockaddr_in *)server_info->ai_addr)->sin_addr)){
		// Compares IP address sent to and received from
        fprintf(stderr, "Error: sent and received IP address does not match!\n");
	} else {
		// Passed initial checks, convert to struct
		packet_to_struct(&recv_packet, buffer);
		// More sanity checks as per RFC4330 recommendations
		if (verify_packet(&recv_packet, &transmit_time) == 1){
			// Skip packet if failed checks
			return 1;
		}
		print_packet(&recv_packet);
	}
	
	// Mnimum of 15ms as per request RFC 4330 requirements
	usleep(15);
    return 0;
}

void build_packet(unsigned char sntp_packet[], struct timeval* transmit_time){
	// Set LI to 0
	sntp_packet[0] |= NOLEAP;
	// Set VN to 4 as SNTPv4
	sntp_packet[0] |= SNTPV4;
	// Set Mode to 3 as client
	sntp_packet[0] |= CLIENTMODE;
    
	// Get current UNIX timestamp, convert to NTP, write to packet.
	gettimeofday(transmit_time, NULL);
	unix_to_ntp_time(transmit_time);
   	transmit_time->tv_sec = htonl(transmit_time->tv_sec);
	transmit_time->tv_usec = htonl(transmit_time->tv_usec);
	memcpy(&sntp_packet[40], &transmit_time->tv_sec, 4); 
	memcpy(&sntp_packet[44], &transmit_time->tv_usec, 4);
}

void unix_to_ntp_time(struct timeval *time){
	time->tv_sec += STARTOFTIME;
	time->tv_usec = ((time->tv_usec + 1) * USECSHIFT);
}

void packet_to_struct(struct NTPPacket* recv_packet, unsigned char buf[]){
    // LI, VN, Mode, Stratum, Poll Interval, Precision
    recv_packet->leap = ((buf[0] >> 6) & 3);
    recv_packet->version = ((buf[0] >> 3) & 7);
    recv_packet->mode = (buf[0] & 7);
    recv_packet->stratum = buf[1];
    recv_packet->poll_int = pow(2,buf[2]);
    recv_packet->precision = !buf[3] ? 0 : log(buf[3]) / log(2);

    // Root Delay
	memcpy(&recv_packet->root_delay_sec, &buf[4], 2);
	recv_packet->root_delay_sec = ntohs(recv_packet->root_delay_sec);
	memcpy(&recv_packet->root_delay_frac, &buf[6], 2);
	recv_packet->root_delay_frac = ntohs(recv_packet->root_delay_frac);

	// Root Dispersion
	memcpy(&recv_packet->root_disp_sec, &buf[8], 2);
	recv_packet->root_disp_sec = ntohs(recv_packet->root_disp_sec);
	memcpy(&recv_packet->root_disp_frac, &buf[10], 2);
	recv_packet->root_disp_frac = ntohs(recv_packet->root_disp_frac);

	// Reference ID
    memcpy(&recv_packet->ref_id, &buf[12], 4);
    recv_packet->ref_id = ntohl(recv_packet->ref_id);

	// TIMESTAMP DATA
    // Reference Timestamp
    memcpy(&recv_packet->ref_time, &buf[16], 8);
    recv_packet->ref_time[0] = ntohl(recv_packet->ref_time[0]);
    recv_packet->ref_time[1] = ntohl(recv_packet->ref_time[1]);

    // Originate Timestamp
    memcpy(&recv_packet->orig_time, &buf[24], 8);
    recv_packet->orig_time[0] = ntohl(recv_packet->orig_time[0]);
    recv_packet->orig_time[1] = ntohl(recv_packet->orig_time[1]);

    // Received Timestamp
    memcpy(&recv_packet->recv_time, &buf[32], 8);
    recv_packet->recv_time[0] = ntohl(recv_packet->recv_time[0]);
    recv_packet->recv_time[1] = ntohl(recv_packet->recv_time[1]);

    // Transmit Timestamp
    memcpy(&recv_packet->trans_time, &buf[40], 8);
    recv_packet->trans_time[0] = ntohl(recv_packet->trans_time[0]);
    recv_packet->trans_time[1] = ntohl(recv_packet->trans_time[1]);

    //OFFSET & DELAY
    //Offset ((Originate - Reference) * (Receive - Transmit) / 2)
    long offsetSec = (((recv_packet->orig_time[0] - recv_packet->ref_time[0]) +
                        (recv_packet->recv_time[0] - recv_packet->trans_time[0])) / 2);
    long offsetFrac = (((recv_packet->orig_time[1] - recv_packet->ref_time[1]) +
                        (recv_packet->recv_time[1] - recv_packet->trans_time[1])) / 2);
	recv_packet->offset = offsetSec + ((double)offsetFrac / TOFRACTION);

	//Delay ((Transmit - Reference) - (Receive - Originate))
	long delaySec = ((recv_packet->trans_time[0] - recv_packet->ref_time[0]) -
                        (recv_packet->recv_time[0] - recv_packet->orig_time[0]));
	long delayFrac = ((recv_packet->trans_time[1] - recv_packet->ref_time[1]) -
                        (recv_packet->recv_time[1] - recv_packet->orig_time[1]));
	recv_packet->delay = delaySec + ((double)delayFrac / TOFRACTION);
}

int verify_packet(struct NTPPacket* recv_packet, struct timeval* transmit_time){
    // Check if clock unsynchronised
    if(recv_packet->leap == 3){
		printf("Clock unsynchronised, packet ignored.\n\n");
        return 1;
    }
    
    // Check if version not SNTP v4
    if(recv_packet->version != 4){
        printf("Note: Old SNTP version");
    }
    
    // Check if mode not server
    if(recv_packet->mode != 4){
         printf("Mode not set to server, packet ignored.\n\n");
        return 1;
    }
    
    // Check if kiss of death
    if(recv_packet->stratum == 0){
        printf("Stratum set to kiss of death, packet ignored.\n\n");
        return 1;
    }
    
    // Check if matching transmitted and originate timestamps
    if(ntohl(transmit_time->tv_sec) != recv_packet->orig_time[0] ||
       ntohl(transmit_time->tv_usec) != recv_packet->orig_time[1]){
        printf("Transmitted and originate timestamps do not match.\n\n");
        return 1;
    }        
    return 0;
}

void print_packet(struct NTPPacket* recv_packet){
    //Output Packet Details
    printf("***********************************************\n");
    printf("Recieved Packet Details: \n");
    printf("======================== \n\n");
    printf(" Leap Indicator:          %d\n",recv_packet->leap);
    printf(" Version Number:          %d\n",recv_packet->version);
    printf(" Mode:                    %d\n",recv_packet->mode);
    printf(" Stratum:                 %d\n",recv_packet->stratum);
    printf(" Poll Interval:           %lf\n",recv_packet->poll_int);
    printf(" Precision:               %lf\n",recv_packet->precision);
    printf(" Root Delay:              %d.%.5d\n", recv_packet->root_delay_sec,recv_packet->root_delay_frac);
    printf(" Root Dispersion:         %d.%.5d\n", recv_packet->root_disp_sec,recv_packet->root_disp_frac);

    if(recv_packet->stratum == 1){
    	resolve_ref_id(recv_packet->ref_id);
    } else if(recv_packet->stratum >= 2 && recv_packet->stratum <=15){
    	//printf(" Reference Identifier:    %s\n\n", inet_ntop);
    } else {
    	printf(" Reference Identifier:    Private\n\n");
    }

    printf("Recieved Timestamp Data: \n");
    printf("======================== \n\n");
    printf(" Reference Timestamp:     %lu.%.10lu\n", recv_packet->ref_time[0],recv_packet->ref_time[1]);
    printf(" Originate Timestamp:     %lu.%.10lu\n",recv_packet->orig_time[0],recv_packet->orig_time[1]);
    printf(" Receive Timestamp:       %lu.%.10lu\n",recv_packet->recv_time[0],recv_packet->recv_time[1]);
    printf(" Transmit Timestamp:      %lu.%.10lu\n\n\n",recv_packet->trans_time[0],recv_packet->trans_time[1]);

    printf("Offset & Delay: \n");
    printf("=============== \n\n");
    printf(" Offset:                  %.10f\n", recv_packet->offset);
    printf(" Delay:                   %.10f\n", recv_packet->delay);
    printf("************************************************\n");
    printf("\n\n");

}

void resolve_ref_id(long identifier){
	printf(" Reference Identifier:    ");
	switch(identifier){
		case 0x4c4f434c: 	printf("Uncal Local Clock"); break;
		case 0x4345534d: 	printf("Calibrated Cesium Clock"); break;
		case 0x5242444d: 	printf("Calibrated Rubidium Clock"); break;
		case 0x50505300:
		case 0x505053:		printf("Calibrated Quartz clock or pps source"); break;
		case 0x49524947:	printf("Inter-Range Instrumentation Group"); break;
		case 0x41435453:	printf("NIST Tel Modem Service"); break;
		case 0x55534e4f: 	printf("USNO Tel Modem Service"); break;
		case 0x50544200:
		case 0x505442:		printf("PTB (Germany) Tel Modem Service"); break;
		case 0x54444600:
		case 0x544446:		printf("Allouis (France) Radio 164 kHz"); break;
		case 0x44434600:
		case 0x444346:		printf("Mainflingen (Germany) Radio 77.5 kHz"); break;
		case 0x4d534600:
		case 0x4d5346:		printf("Rugby (UK) Radio 60 kHz"); break;
		case 0x57575600:
		case 0x575756:		printf("Ft. Collins (US) Radio 2.5, 5, 10, 15, 20 MHz"); break;
		case 0x57575642:	printf("Boulder (US) Radio 60 kHz"); break;
		case 0x57575648:	printf("Kauai Hawaii (US) Radio 2.5, 5, 10, 15 MHz"); break;
		case 0x43485500:
		case 0x434855:		printf("Ottawa (Canada) Radio 3330, 7335, 14670 kHz"); break;
		case 0x4c4f5243:	printf("LORAN-C Radionavigation System"); break;
		case 0x4f4d4547:	printf("OMEGA Radionavigation System"); break;
		case 0x47505300:
		case 0x475053:		printf("GPS"); break;
	}
	printf("\n\n\n");
}

void add_server_details(struct NTPPacket* recv_packet, struct manycastDetails servers[], struct sockaddr_in* recv_addr){
	static int server_count = 0;
	if(server_count < 11){
		servers[server_count].id = server_count;
		servers[server_count].ad = recv_addr->sin_addr;
		servers[server_count].packet = *recv_packet;
		server_count++;
		qsort(servers, server_count, sizeof(struct manycastDetails), sort_by_delay);
		qsort(servers, server_count, sizeof(struct manycastDetails), sort_by_stratum);
	} 
	else{
		servers[10].id = server_count;
		servers[10].ad = recv_addr->sin_addr;
		servers[10].packet = *recv_packet;
		server_count++;
		qsort(servers, 11, sizeof(struct manycastDetails), sort_by_delay);
		qsort(servers, 11, sizeof(struct manycastDetails), sort_by_stratum);
	}
}

int sort_by_stratum(const void *a, const void *b){
    const struct manycastDetails *s1 = (struct manycastDetails*)a;
    const struct manycastDetails *s2 = (struct manycastDetails*)b;
    // Lower stratum prioritised
    if (s1->packet.stratum < s2->packet.stratum){
    	return -1;
    }
    else if (s1->packet.stratum > s2->packet.stratum){
    	return +1;
    }
	return 0;
}

int sort_by_delay(const void *a, const void *b){
    const struct manycastDetails *d1 = (struct manycastDetails*)a;
    const struct manycastDetails *d2 = (struct manycastDetails*)b;
    // Lower delay prioritised
    if (d1->packet.delay < d2->packet.delay){
    	return -1;
    }
    else if (d1->packet.delay > d2->packet.delay){
    	return +1;
    }
	return 0;
}

void print_server_details(struct manycastDetails servers[]){
	int i;
	for(i = 0; i < 11; i++)
	{

			printf("ID: %d, Offset: %lf, Delay: %lf, Stratum: %d\n",
			servers[i].id, servers[i].packet.offset,
			servers[i].packet.delay, servers[i].packet.stratum);

	}
	printf("\n");
}
