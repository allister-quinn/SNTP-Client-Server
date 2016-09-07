/*****************************************************
* Program name: manyserver 
*
* Module ID: UFCFQ4-30-2
* Module Name: Computer Networks and Operating Systems
*
* First written on 10/03/2015
*
* Authors: Allister Quinn - 13000014
*	       Ben Slatter    - 13007555
*
* Program Description:
* Manycast SNTP server. Recieves a SNTP packet request
* from an SNTP client, and sends back SNTP packet.
*
*****************************************************/
/*  Includes */

#include <stdio.h>
#include <stdlib.h> 	// exit()
#include <errno.h> 		// perror()
#include <string.h>		// memset()
#include <sys/socket.h> // socket
#include <netinet/in.h> // network
#include <arpa/inet.h> 	// network
#include <sys/time.h> 	// time
#include <stdint.h> 	// uint32_t type
#include <unistd.h> 	// fork()
#include <sys/wait.h>	// fork()
#include <signal.h>		// signal
#include <time.h>		// rand

/****************************************************/
/*  Defines */

// Size of SNTP packet
#ifndef PACKETSIZE
#define PACKETSIZE 48
#endif 

// Secs since 1/1/1970 required in unix_to_ntp_time
#ifndef STARTOFTIME
#define STARTOFTIME 2208988800UL
#endif

// Used to shift usecs in unix_to_ntp_time
#ifndef USECSHIFT 
#define USECSHIFT (1LL << 32) * 1.0e-6
#endif

// Used in calculating offset and delay. 
#ifndef TOFRACTION
#define TOFRACTION 10000000000 
#endif 

// Set packet LI to no leap.
#ifndef NOLEAP
#define NOLEAP 0x0 
#endif 

// Set packet mode to client.
#ifndef SERVERMODE
#define SERVERMODE 0x4 
#endif 

// Set packet VN to SNTPv4.
#ifndef SNTPV4
#define SNTPV4 0x20 
#endif 

// Set packet stratum to secondary.
#ifndef STRATUM_2
#define STRATUM_2 0x2 
#endif 

/****************************************************/
/*  Functions */

/*********************************************************************************************
* Name: void unix_to_ntp_time(struct timeval *time)
* Returns:				: void
* Parameters			:
*    *time				: UNIX timestamp
* Created by			: Allister Quinn / Ben Slatter
* Date created			: 07/03/2015
* Description			: Converts a UNIX timestamp into a NTP compatible version. 
* Notes					: None
*********************************************************************************************/
void unix_to_ntp_time(struct timeval *time);
