#include "manyserver.h"

int main(int argc, char * argv[]){

    // Socket variables
    struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
    int sockfd;
    int numbytes;
	socklen_t addr_len = sizeof(server_addr);;
	// SNTP packet to be sent
	char sntp_packet[PACKETSIZE] = {0};
	// Hold timestamps
	struct timeval recv_time, transmit_time;
	// Client packet buffer
	char buf[PACKETSIZE];
	

	// Check arguments entered
	if (argc != 2){
		fprintf(stderr, "usage: Invalid arguments. Enter correct IP/hostname and port.\n");
		exit(1);
	}

	// Create listening socket
	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		perror("Listener socket error.");
		exit(1);
	}
	
	// Set Unix socket to allow address re-use
	int yes = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
    &yes, sizeof( int)) == -1){
        perror( "Server setsockopt");
        exit( 1);
    }
	
	// Set server address details
	memset(&server_addr, 0, addr_len);
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(strtol(argv[1], NULL, 10)); 
	server_addr.sin_addr.s_addr = inet_addr("224.0.1.1"); // any of server IP addrs

	// Bind socket
	if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr)) == -1){
		perror("Listener bind");
		exit(1);
	}
	
	// Listen for requests
	int pid;
	while (1){ 
		// Receive packet
		if ((numbytes = recvfrom(sockfd, buf, PACKETSIZE, 0, (struct sockaddr *) &client_addr, &addr_len)) == -1){
			perror("Listener recvfrom: ");
			exit(1);
		}
			
		// Record recieved time, convert to NTP. It is important that 
		// this comes first for greater accuracy.
		gettimeofday(&recv_time, NULL);
		unix_to_ntp_time(&recv_time);
		
		// Do not return packet if not client!
		if((buf[0] & 3) != 3){
			continue;
		}
		
		pid = fork();
		// Fork process
		if (pid < 0){
			perror("Error while forking new process.\n");
			exit(1);
		}
		
		if (pid == 0){
			// Seed random numbers based on PID
			srand(getpid());
			
			// Set LI
			sntp_packet[0] |= NOLEAP;
			// Set VN
			sntp_packet[0] |= SERVERMODE;
			// Set Mode
			sntp_packet[0] |= SNTPV4;
		    // Set Stratum
			sntp_packet[1] = STRATUM_2;
			
			/*// Select random stratum value, for testing purposes.
			int randStratum = rand() % 4 + 1; // No kiss of death.
			switch(randStratum)
			{
				case 0:
				sntp_packet[1] |= 0; // Kiss O Death
				break;
				
				case 1:
				sntp_packet[1] |= 1; // Primary reference
				break;
				
				case 2:
				sntp_packet[1] |= 2; // Secondary reference
				break;
				
				case 3:
				sntp_packet[1] |= 3; // Tertiary reference...
				break;
				
				case 4:
				sntp_packet[1] |= 4; // Primary reference
				break;
			}
			*/
			
			// CREATE TIMESTAMPS			
			// Originate Timestamp
			memcpy(&sntp_packet[24], &buf[40], 8);
			
			// Receive Timestamp
			recv_time.tv_sec = htonl(recv_time.tv_sec);
			recv_time.tv_usec = htonl(recv_time.tv_usec);
			memcpy(&sntp_packet[32], &recv_time.tv_sec, 4);
			memcpy(&sntp_packet[36], &recv_time.tv_usec, 4);
			
			// Transmit Stamp
			gettimeofday(&transmit_time, NULL);
			unix_to_ntp_time(&transmit_time);
			transmit_time.tv_sec = htonl(transmit_time.tv_sec);
			transmit_time.tv_usec = htonl(transmit_time.tv_usec);
			memcpy(&sntp_packet[40], &transmit_time.tv_sec, 4);
			memcpy(&sntp_packet[44], &transmit_time.tv_usec, 4);
			
			/*// Create random reference timestamp, for testing purposes.
			unsigned long r = rand() % 4294967294UL;
			memcpy(&sntp_packet[16], &recv_time.tv_sec, 4);
			sntp_packet[19] -= 10;
			sntp_packet[19] -= (rand() % 20);
			memcpy(&sntp_packet[20], &r, 4);
			*/
			
			// Send SNTP packet back to client
			if ((numbytes = sendto(sockfd, sntp_packet, PACKETSIZE, 0, (struct sockaddr *) &client_addr, sizeof(struct sockaddr))) == -1){
				perror("Talker sendto");
				exit(1);
			}
			
			close(sockfd);
			exit(0);
		}
	}
	return 0;
};

void unix_to_ntp_time(struct timeval *time){
	time->tv_sec += STARTOFTIME;
	time->tv_usec = ((time->tv_usec + 1) * USECSHIFT);
}
