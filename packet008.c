#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <mariadb/mysql.h>
#include <stdlib.h>

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char ip_vhl;          /* version << 4 | header length >> 2 */
        u_char ip_tos;          /* type of service */
        u_short ip_len;         /* total length */
        u_short ip_id;          /* identification */
        u_short ip_off;         /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char ip_ttl;          /* time to live */
        u_char ip_p;            /* protocol */
        u_short ip_sum;         /* checksum */
        struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;       /* source port */
        u_short th_dport;       /* destination port */
        tcp_seq th_seq;         /* sequence number */
        tcp_seq th_ack;         /* acknowledgement number */
        u_char th_offx2;        /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;         /* window */
        u_short th_sum;         /* checksum */
        u_short th_urp;         /* urgent pointer */
};

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

// define db variables ...
MYSQL	*connection=NULL, conn;
MYSQL_RES	*sql_result;
MYSQL_ROW	sql_row;
int	query_stat;
//char query_string[200] = {};
char *query_string = NULL;





void got_packet(u_char *args, const struct pcap_pkthdr *header,
                                        const u_char *packet) {
        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
        }
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
        }
        payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);


        //
        // print Ethernet address
        printf("DATA: dest MAC : %02x:%02x:%02x:%02x:%02x:%02x\n" ,
                                                ethernet->ether_dhost[0],
                                                ethernet->ether_dhost[1],
                                                ethernet->ether_dhost[2],
                                                ethernet->ether_dhost[3],
                                                ethernet->ether_dhost[4],
                                                ethernet->ether_dhost[5]
                                                );
        printf("DATA: src  MAC : %02x:%02x:%02x:%02x:%02x:%02x\n" ,
                                                ethernet->ether_shost[0],
                                                ethernet->ether_shost[1],
                                                ethernet->ether_shost[2],
                                                ethernet->ether_shost[3],
                                                ethernet->ether_shost[4],
                                                ethernet->ether_shost[5]
                                                );
        printf("DATA: ether_type : 0x%X ( %d )\n" ,
                                                ethernet->ether_type,
                                                ethernet->ether_type
                                                );


        // print IP address
        //char ip_src_temp[4] = {};
        //memcpy(&ip_src_temp , &(ip->ip_src) , 4);
        //printf("DATA: IP src : %3u.%3u.%3u.%3u\n" ,
        //              ip_src_temp[0],
        //              ip_src_temp[1],
        //              ip_src_temp[2],
        //              ip_src_temp[3]
        //              );
        char *IPbuffer, *IPbuffer2;
        char IPbuffer_str[16];
        char IPbuffer2_str[16];

        IPbuffer = inet_ntoa(ip->ip_src);
        strcpy(IPbuffer_str, IPbuffer);

        IPbuffer2 = inet_ntoa(ip->ip_dst);
        strcpy(IPbuffer2_str, IPbuffer2);

        printf("DATA: IP src : %s\n", IPbuffer_str);
        printf("DATA: IP dst : %s\n", IPbuffer2_str);

        //
        // print tcp port number
        unsigned short tcp_src_port = 0;
        unsigned short tcp_dst_port = 0;

        tcp_src_port = ntohs(tcp->th_sport);
        tcp_dst_port = ntohs(tcp->th_dport);


        printf("DATA : src Port : %u\n" , tcp_src_port );
        printf("DATA : dst Port : %u\n" , tcp_dst_port );

        //
        // print payload data

        char *payload_curr_ptr_last = NULL ;
        char *payload_curr_ptr = NULL;
        int payload_curr_len = 0;
        char payload_line_temp[500] = {};
        char *payload_max = (char*)packet + header->len;
        int payload_len = 0;

        #define PAYLOAD_COPY_SIZE 2048
        #define PAYLOAD_COPY_SIZE 1048576
        char payload_copy[ PAYLOAD_COPY_SIZE ];
        memset(payload_copy, 0x00 , PAYLOAD_COPY_SIZE);
        //payload_len = header->len - ip->ip_len * 4 - 20 ;
        payload_len = header->len - SIZE_ETHERNET - size_ip - size_tcp ;
        payload_max = (char*)payload_copy + header->len;

        printf("DATA : payload(%d) : %s .\n" , payload_len , payload );

        if ( payload_len > 0 ) {

                memcpy(payload_copy , payload , payload_len ) ;

                char *payload_curr_ptr_last = payload_copy ;
                char *payload_curr_ptr = payload_copy ;

                // ptr_last      ptr
                // GET / HTTP/1.1\r\nHost: nginx.org\r\nAccept:

                while ( 1 ) {
                        payload_curr_ptr = strstr( payload_curr_ptr_last , "\r\n" );
                        if ( payload_curr_ptr > payload_max ) {
                                break;
                        }
                        if ( payload_curr_ptr == NULL ) {
                                //break;
                                payload_curr_ptr = payload_max ;
                        }
                        payload_curr_len = payload_curr_ptr - payload_curr_ptr_last;
                        printf("DEBUG: payload_curr_len == %d .\n" , payload_curr_len );
						
						int host_exist = 0 ;
						char host_value[512] = { 0x00 } ;
						int compare_result = 0 ;
						int result = 0 ;
						
                        if ( payload_curr_len >= 0 ) {
                                memset ( payload_line_temp , 0x00 , 500 );
                                strncpy(payload_line_temp , payload_curr_ptr_last , payload_curr_len);
                                printf("DATA : payload(line)(mem_range:%p,%p) : %s .\n" , 
									payload_curr_ptr_last , payload_curr_ptr , payload_line_temp );
								
								// payload_line_temp == "Host: nginx.org"  
								host_exist = strncmp ( payload_line_temp , "Host: " , 6 ) ;
								if ( host_exist == 0 ) {
									printf("NOTICE: \"Host: \" was founded !!!\n");
									strcpy (host_value , payload_line_temp + 6);
									printf("DEBUG: host_value = %s .\n" , host_value ) ;
									
									// compare logic
									compare_result = strcmp( "nginx.org" , host_value ) ;
									if ( compare_result != 0 ) {
										result = 1 ;
									}
									
									sprintf(query_string,
										"INSERT INTO tb_packet_log "
											"( domain , result , "
											"  src_ip , dst_ip , "
											"  src_port , dst_port , pkt_size )"
											" VALUES "
											"( '%s' , %d , "
											"  '%s' , '%s' , "
											"   %u  ,  %u , %d )",
											host_value , result ,
											IPbuffer_str , IPbuffer2_str , 
											tcp_src_port , tcp_dst_port , header->len 
										);
									
									query_stat = mysql_query( connection, 
													query_string );
									if ( query_stat != 0 ) {
										fprintf( stderr, "ERR: Mysql query"
													" error : %s",
										mysql_error(&conn) );
										return 1;
									} else {
										fprintf( stdout, "NOTICE: "
												"insert OK.\n" );
									}
									
								}
								// end if ( host_exist ) .
                        } else {
                                // stop while loop.
                                break;
                        }

                        payload_curr_ptr_last = payload_curr_ptr + 2 ;
                }
        } else if ( payload_len > 2000 ) {
                        printf("ERROR: payload_len > 2000 , ( %d ) !!!\n" , payload_len ) ;
                }


        printf("got_packet with length of [%d]\n", header->len);

}

int main(int argc, char *argv[])
{
        pcap_t *handle; /* Session handle */
        char *dev;      /* Device to sniff on */
        char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
        struct bpf_program fp;          /* The compiled filter expression */
        char filter_exp[] = "tcp port 80";      /* The filter expression */
        bpf_u_int32 mask;               /* The netmask of our sniffing device */
        bpf_u_int32 net;                /* The IP of our sniffing device */
        struct pcap_pkthdr header;      /* The header that pcap gives us */
        const u_char *packet;           /* The actual packet */

        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
                return(2);
        }

        printf("Device: %s\n", dev);

        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                fprintf(stderr, "Can't get netmask for device %s\n", dev);
                net = 0;
                mask = 0;
        }
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
                return(3);
        } else {
                printf("INFO: pcap_open_live OK\n");
        }

        if (pcap_datalink(handle) != DLT_EN10MB) {
                fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
                return(2);
        } else {
                printf("INFO: pcap_datalink OK\n");
        }

        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        } else {
                printf("INFO: pcap_compile OK\n");
        }

        if (pcap_setfilter(handle, &fp) == -1) {
                fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
                return(2);
        } else {
                printf("INFO: pcap_setfilter OK\n");
        }

        //for ( int i = 0 ; i < 20 ; i ++ ) {
        //      /* Grab a packet */
        //      packet = pcap_next(handle, &header);
        //      /* Print its length */
        //      printf("Jacked a packet with length of [%d]\n", header.len);
        //}

		mysql_init(&conn);

		connection = mysql_real_connect(
				&conn,	// mysql handler
				"localhost",	// host
				"root",	// id
				"rootpass",	// pw
				"project_db",	// db_name
				3306,		// port
				(char*)NULL,	// 
				0		// 
			);

		if ( connection == NULL ) {
			fprintf(stderr, "ERROR: "
				"Mysql connection error: %s",
				mysql_error(&conn));
			return 1;
		}

		query_string = malloc(10485760);

		memset( query_string , 0x00 , 10485760);
		


        pcap_loop(handle, 20, got_packet, NULL);

        /* And close the session */
        if ( handle != NULL ) {
                pcap_close(handle);
                handle = NULL;
        }
		
		// close mariadb handle
		if ( query_string != NULL ) {
			free(query_string);
			query_string = NULL;
		} else {
			fprintf(stderr,
				"WARNING: "
				"query_string is already free "
				"(%s:%d (%s))!!!\n",
				__FILE__, __LINE__ , __FUNCTION__);
		}
		
		if ( sql_result != NULL ) 
		{
			mysql_free_result(sql_result);
			sql_result = NULL;
		} else {
			fprintf(stderr,
				"WARNING: "
				"sql_result is already free "
				"(%s:%d (%s))!!!\n",
				__FILE__, __LINE__ , __FUNCTION__);
		}
		
		// 마리아 DB 접속종료
		if ( connection != NULL ) {
			mysql_close(connection);
			connection = NULL;
			printf("INFO: DB handle closed successfully\n");
		} else {
			fprintf(stderr,"WARN: DB handle is already closed\n");
		}

        return(0);
}
