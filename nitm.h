#ifndef _MAILSNIFFER_H
#define _MAILSNIFFER_H

struct etherhdr {
	u_int8_t  ether_dhost[ETHER_ADDR_LEN];	/* destination eth addr	*/
	u_int8_t  ether_shost[ETHER_ADDR_LEN];	/* source ether addr	*/
	u_int16_t ether_type;			/* packet type ID field	*/
};


#endif //_MAILSNIFFER_H