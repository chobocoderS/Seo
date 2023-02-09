#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <mariadb/my_global.h>
#include <mariadb/mysql.h>
#include <errno.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
//#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <sys/time.h>
#include <time.h>
#include <math.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/tcp.h>
#include <netdb.h>

#define SUPPORT_OUTPUT


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

struct pseudohdr {
        u_int32_t   saddr;
        u_int32_t   daddr;
        u_int8_t    useless;
        u_int8_t    protocol;
        u_int16_t   tcplength;
};

struct struct_domain_list {
	int id;
	char domain[256];
	char created_at[100];
	char comment[150];
};

struct struct_domain_list *domain_list;
int domain_list_cnt;


// global variables ...
char if_bind_global[] = "enp0s3" ;
//char if_bind_global[] = "lo" ;
int if_bind_global_len = 6 ;
//int if_bind_global_len = 2 ;

int sendraw_mode = 1;



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


int print_chars(char print_char, int nums);

void
print_payload(const u_char *payload, int len);

void
print_payload_right(const u_char *payload, int len);

void
print_hex_ascii_line(const u_char *payload, int len, int offset);

void
print_hex_ascii_line_right(const u_char *payload, int len, int offset);


unsigned short in_cksum(u_short *addr, int len);

int sendraw ( u_char* pre_packet, int mode );

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

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
		


        pcap_loop(handle, 0, got_packet, NULL);

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
									//compare_result = strcmp( "nginx.org" , host_value ) ;
									compare_result = strcmp( "http.badssl.com" , host_value ) ;
									if ( compare_result != 0 ) {
										result = 1 ;
									} else {
										result = 0 ;
										// 차단패킷 발송
										int sendraw_result = 0;
										sendraw_result = sendraw(packet, 1);
										//sendraw_result = sendraw(packet, sendraw_mode);
										
										if ( sendraw_result == 1 ) {
											printf("INFO: sendraw success(%d).\n", 
													sendraw_result);
										} else {
											printf("ERROR: sendraw failed !!!(%d).\n", 
													sendraw_result);
										}
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


unsigned short in_cksum(u_short *addr, int len)
{
        int         sum=0;
        int         nleft=len;
        u_short     *w=addr;
        u_short     answer=0;
        while (nleft > 1){
            sum += *w++;
            nleft -= 2;
        }

        if (nleft == 1){
            *(u_char *)(&answer) = *(u_char *)w ;
            sum += answer;
        }

        sum = (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        answer = ~sum;
        return(answer);
}

int sendraw( u_char* pre_packet, int mode)
{
		const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */

		u_char packet[1600];
        int raw_socket, recv_socket;
        int on=1, len ;
        char recv_packet[100], compare[100];
        struct iphdr *iphdr;
        struct tcphdr *tcphdr;
        struct in_addr source_address, dest_address;
        struct sockaddr_in address, target_addr;
        struct pseudohdr *pseudo_header;
        struct in_addr ip;
        struct hostent *target;
        int port;
        int loop1=0;
        int loop2=0;
        int pre_payload_size = 0 ;
		u_char *payload = NULL ;
		int size_vlan = 0 ;
		int size_vlan_apply = 0 ;
		int size_payload = 0 ;
        int post_payload_size = 0 ;
        int sendto_result = 0 ;
	    int rc = 0 ;
	    //struct ifreq ifr ;
		char * if_bind ;
		int if_bind_len = 0 ;
		int setsockopt_result = 0 ;
		int prt_sendto_payload = 0 ;
		char* ipaddr_str_ptr ;

		int warning_page = 1 ;
		int vlan_tag_disabled = 0 ;

		int ret = 0 ;

		#ifdef SUPPORT_OUTPUT
		print_chars('\t',6);
		printf( "\n[raw socket sendto]\t[start]\n\n" );

		if (size_payload > 0 || 1) {
			print_chars('\t',6);
			printf("   pre_packet whole(L2-packet-data) (%d bytes only):\n", 100);
			print_payload_right(pre_packet, 100);
		}
		//m-debug
		printf("DEBUG: (u_char*)packet_dmp ( in sendraw func ) == 0x%p\n", pre_packet);
		#endif

        for( port=80; port<81; port++ ) {
			#ifdef SUPPORT_OUTPUT
			print_chars('\t',6);
			printf("onetime\n");
			#endif
			// raw socket 생성
			raw_socket = socket( AF_INET, SOCK_RAW, IPPROTO_RAW );
			if ( raw_socket < 0 ) {
				print_chars('\t',6);
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				fprintf(stderr,"Error in socket() creation - %s\n", strerror(errno));
				return -2;
			}

			setsockopt( raw_socket, IPPROTO_IP, IP_HDRINCL, (char *)&on, sizeof(on));

			if ( if_bind_global != NULL ) {
				setsockopt_result = setsockopt( raw_socket, SOL_SOCKET, SO_BINDTODEVICE, if_bind_global, if_bind_global_len );

				if( setsockopt_result == -1 ) {
					print_chars('\t',6);
					fprintf(stderr,"ERROR: setsockopt() - %s\n", strerror(errno));
					return -2;
				}
				#ifdef SUPPORT_OUTPUT
				else {
					print_chars('\t',6);
					fprintf(stdout,"OK: setsockopt(%s)(%d) - %s\n", if_bind_global, setsockopt_result, strerror(errno));
				}
				#endif

			}

			ethernet = (struct sniff_ethernet*)(pre_packet);
			if ( ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x81\x00" ) {
				#ifdef SUPPORT_OUTPUT
				printf("vlan packet\n");
				#endif
				size_vlan = 4;
				memcpy(packet, pre_packet, size_vlan);
			} else if (ethernet->ether_type == (unsigned short)*(unsigned short*)&"\x08\x00" ) {
				#ifdef SUPPORT_OUTPUT
				printf("normal packet\n");
				#endif
				size_vlan = 0;
			} else {
				fprintf(stderr,"NOTICE: ether_type diagnostics failed .......... \n");
			}

			vlan_tag_disabled = 1 ;
			if ( vlan_tag_disabled == 1 ) {
				size_vlan_apply = 0 ;
				memset (packet, 0x00, 4) ;
			} else {
				size_vlan_apply = size_vlan ;
			}
                // TCP, IP 헤더 초기화
                iphdr = (struct iphdr *)(packet + size_vlan_apply) ;
                memset( iphdr, 0, 20 );
                tcphdr = (struct tcphdr *)(packet + size_vlan_apply + 20);
                memset( tcphdr, 0, 20 );

				#ifdef SUPPORT_OUTPUT
                // TCP 헤더 제작
                tcphdr->source = htons( 777 );
                tcphdr->dest = htons( port );
                tcphdr->seq = htonl( 92929292 );
                tcphdr->ack_seq = htonl( 12121212 );
				#endif

				source_address.s_addr = 
				((struct iphdr *)(pre_packet + size_vlan + 14))->daddr ;
				// twist s and d address
				dest_address.s_addr = ((struct iphdr *)(pre_packet + size_vlan + 14))->saddr ;		// for return response
				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id ;
				int pre_tcp_header_size = 0;
				char pre_tcp_header_size_char = 0x0;
				pre_tcp_header_size = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->doff ;
				pre_payload_size = ntohs( ((struct iphdr *)(pre_packet + size_vlan + 14))->tot_len ) - ( 20 + pre_tcp_header_size * 4 ) ;

				tcphdr->source = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->dest ;		// twist s and d port
				tcphdr->dest = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->source ;		// for return response
				tcphdr->seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->ack_seq ;
				tcphdr->ack_seq = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->seq  + htonl(pre_payload_size - 20)  ;
				tcphdr->window = ((struct tcphdr *)(pre_packet + size_vlan + 14 + 20))->window ;

                tcphdr->doff = 5;

                tcphdr->ack = 1;
                tcphdr->psh = 1;

                tcphdr->fin = 1;
                // 가상 헤더 생성.
                pseudo_header = (struct pseudohdr *)((char*)tcphdr-sizeof(struct pseudohdr));
                pseudo_header->saddr = source_address.s_addr;
                pseudo_header->daddr = dest_address.s_addr;
                pseudo_header->useless = (u_int8_t) 0;
                pseudo_header->protocol = IPPROTO_TCP;
                pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				// m-debug
				printf("DEBUG: &packet == \t\t %p \n" , &packet);
				printf("DEBUG: pseudo_header == \t %p \n" , pseudo_header);
				printf("DEBUG: iphdr == \t\t\t %p \n" , iphdr);
				printf("DEBUG: tcphdr == \t\t\t %p \n" , tcphdr);
				#endif

				#ifdef SUPPORT_OUTPUT
                strcpy( (char*)packet + 40, "HAHAHAHAHOHOHOHO\x0" );
				#endif

				// choose output content
				warning_page = 5;
				if ( warning_page == 5 ){
					// write post_payload ( redirecting data 2 )
					//post_payload_size = 201 + 67  ;   // Content-Length: header is changed so post_payload_size is increased.
					post_payload_size = 230 + 65  ;   // Content-Length: header is changed so post_payload_size is increased.
                    //memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK" + 0x0d0a + "Content-Length: 1" + 0x0d0a + "Content-Type: text/plain" + 0x0d0a0d0a + "a" , post_payload_size ) ;
					memcpy ( (char*)packet + 40, "HTTP/1.1 200 OK\x0d\x0a"
							"Content-Length: 230\x0d\x0a"
							"Content-Type: text/html"
							"\x0d\x0a\x0d\x0a"
							"<html>\r\n"
							"<head>\r\n"
							"<meta charset=\"UTF-8\">\r\n"
							"<title>\r\n"
							"CroCheck - WARNING - PAGE\r\n"
        						"SITE BLOCKED - WARNING - \r\n"
							"</title>\r\n"
							"</head>\r\n"
							"<body>\r\n"
							"<center>\r\n"
		"<img src=\"http://192.168.1.103:80/warning.png\" alter=\"*WARNING*\">\r\n"
        "<h1>SITE BLOCKED</h1>\r\n"
							"</center>\r\n"
							"</body>\r\n"
							"</html>", post_payload_size ) ;
                }
				pseudo_header->tcplength = htons( sizeof(struct tcphdr) + post_payload_size);

                tcphdr->check = in_cksum( (u_short *)pseudo_header,
                                sizeof(struct pseudohdr) + sizeof(struct tcphdr) + post_payload_size);

                iphdr->version = 4;
                iphdr->ihl = 5;
                iphdr->protocol = IPPROTO_TCP;
                //iphdr->tot_len = 40;
                iphdr->tot_len = htons(40 + post_payload_size);

				#ifdef SUPPORT_OUTPUT
				//m-debug
				printf("DEBUG: iphdr->tot_len = %d\n", ntohs(iphdr->tot_len));
				#endif

				iphdr->id = ((struct iphdr *)(pre_packet + size_vlan + 14))->id + htons(1);

				memset( (char*)iphdr + 6 , 0x40 , 1 );

                iphdr->ttl = 60;
                iphdr->saddr = source_address.s_addr;
                iphdr->daddr = dest_address.s_addr;
                // IP 체크섬 계산.
                iphdr->check = in_cksum( (u_short *)iphdr, sizeof(struct iphdr));

                address.sin_family = AF_INET;

				address.sin_port = tcphdr->dest ;
				address.sin_addr.s_addr = dest_address.s_addr;

				prt_sendto_payload = 0;
				#ifdef SUPPORT_OUTPUT
				prt_sendto_payload = 1 ;
				#endif

				if( prt_sendto_payload == 1 ) {

				print_chars('\t',6);
				printf("sendto Packet data :\n");

				print_chars('\t',6);
				printf("       From: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( source_address ),
								((char*)&source_address.s_addr)[0],
								((char*)&source_address.s_addr)[1],
								((char*)&source_address.s_addr)[2],
								((char*)&source_address.s_addr)[3]
						);
				print_chars('\t',6);
				printf("         To: %s(%hhu.%hhu.%hhu.%hhu)\n",
								inet_ntoa( dest_address ),
								((char*)&dest_address.s_addr)[0],
								((char*)&dest_address.s_addr)[1],
								((char*)&dest_address.s_addr)[2],
								((char*)&dest_address.s_addr)[3]
						);

				switch(iphdr->protocol) {
					case IPPROTO_TCP:
						print_chars('\t',6);
						printf("   Protocol: TCP\n");
						break;
					case IPPROTO_UDP:
						print_chars('\t',6);
						printf("   Protocol: UDP\n");
						return -1;
					case IPPROTO_ICMP:
						print_chars('\t',6);
						printf("   Protocol: ICMP\n");
						return -1;
					case IPPROTO_IP:
						print_chars('\t',6);
						printf("   Protocol: IP\n");
						return -1;
					case IPPROTO_IGMP:
						print_chars('\t',6);
						printf("   Protocol: IGMP\n");
						return -1;
					default:
						print_chars('\t',6);
						printf("   Protocol: unknown\n");
						//free(packet_dmp);
						return -2;
				}

				print_chars('\t',6);
				printf("   Src port: %d\n", ntohs(tcphdr->source));
				print_chars('\t',6);
				printf("   Dst port: %d\n", ntohs(tcphdr->dest));

				payload = (u_char *)(packet + sizeof(struct iphdr) + tcphdr->doff * 4 );

				size_payload = ntohs(iphdr->tot_len) - ( sizeof(struct iphdr) + tcphdr->doff * 4 );

				printf("DEBUG: sizeof(struct iphdr) == %lu \t , \t tcphdr->doff * 4 == %hu \n",
								sizeof(struct iphdr) , tcphdr->doff * 4);

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try1) (%d bytes):\n", ntohs(iphdr->tot_len) - size_payload);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, ntohs(iphdr->tot_len) - size_payload);
				}

				if (size_payload > 0 || 1) {
					print_chars('\t',6);
					printf("   PACKET-HEADER(try2) (%d bytes):\n", 40);
					//print_payload(payload, size_payload);
					print_payload_right((const u_char*)&packet, 40);
				}

				if (size_payload > 0) {
					print_chars('\t',6);
					printf("   Payload (%d bytes):\n", size_payload);
					//print_payload(payload, size_payload);
					print_payload_right(payload, size_payload);
				}
			} // end -- if -- prt_sendto_payload = 1 ;
				if ( mode == 1 ) {
                    sendto_result = sendto( raw_socket, &packet, ntohs(iphdr->tot_len), 0x0,
                                            (struct sockaddr *)&address, sizeof(address) ) ;
					if ( sendto_result != ntohs(iphdr->tot_len) ) {
						fprintf ( stderr,"ERROR: sendto() - %s\n", strerror(errno) ) ;
						ret = -10 ;
					} else {
						ret = 1 ;
					}
		        } // end if(mode)
                //} // end for loop

				if ( (unsigned int)iphdr->daddr == (unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" ) {
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf("##########################################################################################################################\n");
					printf( "address1 == %hhu.%hhu.%hhu.%hhu\taddress2 == %X\taddress3 == %X\n",
							*(char*)((char*)&source_address.s_addr + 0),*(char*)((char*)&source_address.s_addr + 1),
							*(char*)((char*)&source_address.s_addr + 2),*(char*)((char*)&source_address.s_addr + 3),
							source_address.s_addr,	(unsigned int)*(unsigned int*)"\xCB\xF6\x53\x2C" );
				}
                close( raw_socket );
                
        } // end for loop
		#ifdef SUPPORT_OUTPUT
        printf( "\n[sendraw] end .. \n\n" );
		#endif
		//return 0;
		return ret ;
}



int print_chars(char print_char, int nums)
{
	int i = 0;
	for ( i ; i < nums ; i++) {
		printf("%c",print_char);
	}
	return i;
}

void
print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

    return;
}

void
print_hex_ascii_line_right(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;
	int tabs_cnt = 6 ;  // default at now , afterward receive from function caller

	/* print 10 tabs for output to right area	*/
	for ( i = 0 ; i < tabs_cnt ; i++ ) {
		printf("\t");
	}

	/* offset */
	printf("%05d   ", offset);

	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");

	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");

	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

	return;
}

/*
 * print packet payload data (avoid printing binary data)
 */
void
print_payload_right(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;


	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line_right(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line_right(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line_right(ch, len_rem, offset);
			break;
		}
		//m-debug
		if ( offset > 600 ) {
			print_chars('\t',6);
			printf("INFO: ..........    payload too long (print_payload_right func) \n");
			break;
		}
	}

    return;
}


