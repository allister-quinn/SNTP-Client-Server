#include "uniserver.h"

int main(int argc, char * argv[]){

    // Variables
	int sockfd;
	int numbytes;
	// Buffer for the packet received
	char buf[PACKETSIZE]; 
	// Create packet to send back to client
	char serverPacket[PACKETSIZE] = {0}; 
	// Address of this server
	struct sockaddr_in my_addr; 
	// Address of the client that sent the packet req
	struct sockaddr_in their_addr; 
	// Time structs for the receive & transmit stamps
	struct timeval recvTime, transmitTime; 
	socklen_t addr_len;
	    
	if (argc != 2){
		fprintf(stderr, "usage: UDPServer Port\n");
		exit(1);
	}

	if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1){
		perror("Listener socket");
		exit(1);
	}

	memset(&my_addr, 0, sizeof(my_addr)); // Zero struct
	my_addr.sin_family = AF_INET;
	my_addr.sin_port = htons(strtol(argv[1], NULL, 10)); // Port, in network byte order
	my_addr.sin_addr.s_addr = INADDR_ANY; // Any of server IP addresses

	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr)) == -1){
		perror("Listener bind");
		exit(1);
	}

	while (1){ // Keep server listening for connections

		/*********  RECEIVING PACKET  *********/
		addr_len = sizeof(struct sockaddr);

		// Receive Packet
		if ((numbytes = recvfrom(sockfd, buf, PACKETSIZE, 0, (struct sockaddr *) &their_addr, &addr_len)) == -1){
			perror("Listener recvfrom: ");
			exit(1);
		}
		
		// Record recieved timestamp, convert to NTP
		gettimeofday(&recvTime, NULL);
		unixToNtpTime(&recvTime);

		serverPacket[0] = 0x24;// Set version number and mode
		serverPacket[1] = 0x1;

		// TIMESTAMP DATA
		// ORIGINATE TIMESTAMP
		memcpy(&serverPacket[24], &buf[40], 8);

		// RECEIVE TIMESTAMP
		recvTime.tv_sec = htonl(recvTime.tv_sec);
        recvTime.tv_usec = htonl(recvTime.tv_usec);
        memcpy(&serverPacket[32], &recvTime.tv_sec, 4);
        memcpy(&serverPacket[36], &recvTime.tv_usec, 4);

		// TRANSMIT TIMESTAMP
		gettimeofday(&transmitTime, NULL);
		unixToNtpTime(&transmitTime);
        transmitTime.tv_sec = htonl(transmitTime.tv_sec);
        transmitTime.tv_usec = htonl(transmitTime.tv_usec);
        memcpy(&serverPacket[40], &transmitTime.tv_sec, 4);
        memcpy(&serverPacket[44], &transmitTime.tv_usec, 4);

        /*********  SENDING PACKET  *********/
		if ((numbytes = sendto(sockfd, serverPacket, PACKETSIZE, 0, (struct sockaddr *) &their_addr, sizeof(struct sockaddr))) == -1){
			perror("Talker sendto");
			exit(1);
		}
	}
	return 0;
};

// Convert UNIX timestamp into NTP timestamp
void unixToNtpTime(struct timeval *time){
	time->tv_sec += STARTOFTIME; //Add the amount of seconds since 01/01/1900
	time->tv_usec = ((time->tv_usec + 1) * USECSHIFT);
}
