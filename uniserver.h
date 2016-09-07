/*****************************************************
* Program name: uniserver 
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
* Unicast NTP server. Receives a UDP packet request
* and sends back data to the client it was sent from.
*
*****************************************************/
/*  Includes */
#include <stdio.h>
#include <stdlib.h> //exit()
#include <errno.h> // perror()
#include <string.h> // memset()
#include <sys/socket.h> // socket
#include <netinet/in.h> // network
#include <arpa/inet.h> // network
#include <sys/time.h> // time
#include <stdint.h> // uint32_t type
/****************************************************/
/*  Defines */
#ifndef PACKETSIZE
#define PACKETSIZE 48
#endif // PACKETSIZE

#ifndef USECSHIFT //Shifts usecs in unixToNtpTime
#define USECSHIFT (1LL << 32) * 1.0e-6
#endif

#ifndef STARTOFTIME
#define STARTOFTIME 2208988800UL //Secs since epoch
#endif

#ifndef TOFRACTION
#define TOFRACTION 10000000000 //Dividing by this, turns the fraction integer into an actual fraction
#endif // TOFRACTION
/****************************************************/

/*********************************************************************************************
* unixToNtpTime: void unixToNtpTime(struct timeval *time)
*    returns			: N/A
*    *time			: UNIX timestamp
* Created by		: Allister Quinn / Ben Slatter
* Date created		: 07/03/2015
* Description		: Converts the UNIX timestamp into a NTP compatible version. 
* Notes			: None
*********************************************************************************************/
void unixToNtpTime(struct timeval *time);

