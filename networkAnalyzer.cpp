/**************************************************************************
***************************************************************************
******************* Author : Arijit Upadhyaya *****************************
******************* UIN    : 423000515        *****************************
******************* email  : rikie@tamu.edu   *****************************
******************* License: GNU              ****************************
***************************************************************************
***************************************************************************/

#define APP_NAME		"TCP Paucket Reassembler"
#define APP_DESC		"Homework 1, Advanced Networks Security"
#define APP_COPYRIGHT	"Copyright (c) 2015 Arijit Upadhyaya"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* C++ Headers */
#include <unordered_map>
#include <string>
#include <iostream>
#include <sstream>
#include <list>
#include <vector>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

using namespace std;

/* Main data Structure */
unordered_map<string, list<unordered_map<int, const unsigned char *>>> sessions_data;
/* Hashmap to store telnet commands */
unordered_map<int, string> telnet_commands;
unordered_map<int, string> telnet_subcommands;

/* Flag to determine FTP and TELNET Sessions to print the control commands */
int TELNET = 0;
int FTP = 0;

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

/* my function */

void
process_sessions();

void
create_tuple(std::string tuple_key, const u_char *packet);

void
got_packet(u_char *args, struct pcap_pkthdr *header, const u_char *packet);

void
print_app_banner(void);

void
print_app_usage(void);

void
print_my_payload(const unsigned char*);

/*
 * app name/banner
 */
void
print_app_banner(void)
{

	printf("%s - %s\n", APP_NAME, APP_DESC);
	printf("%s\n", APP_COPYRIGHT);
	printf("%s\n", APP_DISCLAIMER);
	printf("\n");

return;
}

/*
 * print help text
 */
void
print_app_usage(void)
{

	printf("Usage: %s [filename]\n", APP_NAME);
	printf("\n");

return;
}

/* Process the packets by inserting the payload int the linked list of hash maps */
void
got_packet(u_char *args, struct pcap_pkthdr *header, const u_char *packet)
{

        static int count = 1;                   /* packet counter */

        /* declare pointers to packet headers */
        const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
        const struct sniff_ip *ip;              /* The IP header */
        const struct sniff_tcp *tcp;            /* The TCP header */
        const u_char *payload;                    /* Packet payload */

        int size_ip;
        int size_tcp;
        int size_payload;

        /* define ethernet header */
        ethernet = (struct sniff_ethernet*)(packet);

        /* define/compute ip header offset */
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip)*4;
        if (size_ip < 20) {
                printf("   * Invalid IP header length: %u bytes\n", size_ip);
                return;
        }

	/* get source and destination IP addresses */
        string s_ip = inet_ntoa(ip->ip_src);
        string d_ip = inet_ntoa(ip->ip_dst);


	/* determine protocol */
        switch(ip->ip_p) {
                case IPPROTO_TCP:
                        break;
                case IPPROTO_UDP:
                        printf("   Protocol: UDP\n");
                        return;
                case IPPROTO_ICMP:
                        printf("   Protocol: ICMP\n");
                        return;
                case IPPROTO_IP:
                        printf("   Protocol: IP\n");
                        return;
                default:
                        printf("   Protocol: unknown\n");
                        return;
        }

        /*
         *  OK, this packet is TCP.
         */

        /* define/compute tcp header offset */
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20) {
                printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                return;
        }
        payload = (const u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

	/* process paylaod if it has some data */
	char *src_port;
        if (size_payload > 0) {
		/* create the unique hash of four tuple and store the payload with sequence number */
		u_char *temp_payload = (u_char *) malloc(sizeof(u_char) * size_payload);
		memcpy(temp_payload,payload,size_payload);	
		
		stringstream ss;
		ss << s_ip << "_" << ntohs(tcp->th_sport) << "_" << d_ip << "_" << ntohs(tcp->th_dport);
		string tuple_string = ss.str();
		
		unordered_map<int, const unsigned char *> temp_data;
		temp_data.insert({ntohl(tcp->th_seq),temp_payload});
		sessions_data[tuple_string].push_back(temp_data);
        }
	count++;
return;
}

void print_telnet_commands(int command) {
	telnet_commands = {{240,"SE"}, {241, "NOP"}, {242, "Data Mark"}, {243, "Break"}, {244, "Interrupt Process"}, {245, "Abort output"}, {246, "Are You There"}, {247, "Erase Characters"}, {248, "Erase Line"}, 
				{249, "Go ahead"}, {250, "SB"}, {251, "WILL"}, {252, "WON'T"}, {253, "DO"}, {254, "DON'T"}, {255, "IAC"}};

	telnet_subcommands = {{0,"TRANSMIT-BINARY"}, {1, "ECHO"}, {2, "Reconnection"}, {3, "SUPPRESS-GO-AHEAD"}, {4, "Approx Message Size Negotiation"}, {5, "STATUS"}, {6, "TIMING-MARK"},
				{7, "RCTE"}, {8, "Output Line Width."}, {9, "Output Page Size."}, {10, "NAOCRD"}, {11, "NAOHTS"}, {12, "NAOHTD"}, {13, "NAOFFD"}, {14, "NAOVTS"},
				{15, "NAOVTD"}, {16, "NAOLFD"}, {17, "Extended ASCII."}, {18, "LOGOUT, Logout."}, {19, "BM, Byte Macro"}, {20, "Data Entry Terminal."},
				{21, "SUPDUP"}, {22, "SUPDUP-OUTPUT"}, {23, "SEND-LOCATION"}, {24, "TERMINAL-TYPE"}, {25, "END-OF-RECORD"}, {26, "TUID, TACACS User Identification"},
				{27, "OUTMRK"}, {28, "TTYLOC"}, {29, "Telnet 3270 Regime"}, {30, "X.3 PAD"}, {31, "NAWS"}, {32, "Terminal Speed."}, {33, "Remote Flow Control"},
				{34, "Linemode"}, {35, "X Display Location"}, {36, "Environment Option"}, {37, "AUTHENTICATION"}, {38, "Encryption Option"}, {39, "New Environment Option"},
				{40, "TN3270E"}, {41, "XAUTH"}, {42, "CHARSET"}, {43, "RSP, Telnet Remote Serial Port"}, {44, "Com Port Control Option"}, {45, "Telnet Suppress Local Echo"},
				{46, "Telnet Start TLS"}, {47, "KERMIT"}, {48, "SEND-URL"}, {49, "FORWARD_X"}, {138, "TELOPT PRAGMA LOGON"}, {139, "TELOPT SSPI LOGON"},
				{140, "TELOPT PRAGMA HEARTBEAT"}}; 

	if(telnet_commands.count(command)) 
		cout << " The TELNET Command is: " << telnet_commands[command] << endl;
	if(telnet_subcommands.count(command))
		cout << "The TELNET Subcommand is: " << telnet_subcommands[command] << endl;
	
return;
}

void print_my_payload(const u_char *payload) {

	const u_char *ch = payload;
	while(*ch) {
		if (*ch == '\n')
			printf("\n");
		else if (isprint(*ch))
			printf("%c", *ch);
		else if (TELNET == 1) {
			print_telnet_commands(*ch);
			printf("%d\n", *ch);
		}
		else if (FTP == 1) {
			printf("%d\n", *ch);
		}
		else printf("%d", *ch);
	ch++;
	}
	TELNET = 0;
	FTP = 0;
return;
}

/* Print the session details before we print the payload */
void print_head(string tuple_str) {
	vector<string> strings;
       	istringstream f(tuple_str);
        string s;
        while (getline(f, s, '_')) {
        	strings.push_back(s);
	}
	cout << endl;
	cout << "Data for session of Source IP: " << strings[0] << ", Source Port: " << strings[1] << ", Destination IP: " << strings[2] << " and Destination Port: " << strings[3] << " follows: "<< endl;
	if(!strings[1].compare("80") || !strings[3].compare("80"))
		cout << "The protocol is HTTP" << endl; 	
	else if(!strings[1].compare("23") || !strings[3].compare("23")) {
		cout << "The protocol is TELNET" << endl;
		TELNET = 1;
	}
	else if(!strings[1].compare("21") || !strings[3].compare("21")) {
		cout << "The protocol is FTP and the connection is CONTROL" << endl;
		FTP = 1;
	}
	else if(!strings[1].compare("20") || !strings[3].compare("20")) {
		cout << "The protocol is FTP and the connection is DATA" << endl;
		FTP = 1;
	}
	
}

/* After we done with parsing the packets now go thought the Data Structure and print the payloads after reassembly */
void process_sessions() {

	list<int> sequence_list;
	unordered_map<int, const u_char *> temp_hash;

	for(unordered_map<string, list<unordered_map<int, const unsigned char *>>>::iterator it = sessions_data.begin(); it != sessions_data.end(); ++it ){ // get the list
		for(list<unordered_map<int, const unsigned char *>>::iterator lit = it->second.begin(); lit !=it->second.end(); ++lit) { // get the seq->payload map
			for(unordered_map<int, const unsigned char *>::iterator uit = lit->begin(); uit !=lit->end(); ++uit) { // process the payload for a unique session
				sequence_list.push_back(uit->first); // create a list with seq numbers to sort it later
				temp_hash[uit->first] = uit->second; // create hash with seq->payload
			}
		}
		printf("\n\n*********************************This is a new session********************************** \n");
		print_head(it->first); // print the information of each session like source, destination and protocol
		printf("\n");
		sequence_list.sort(); // arrange the sequence numbers in ascendind number
                for(list<int>::iterator i = sequence_list.begin(); i != sequence_list.end(); ++i) {
			print_my_payload(temp_hash[*i]); // since the seq have been arranged in non-decreasing manner, just print sequentially
                }
		printf("\n\n\n");
		temp_hash.clear();	
		sequence_list.clear();
		printf("*****************************************End of session*************************************\n\n");
	}
return;
}

// The main entry of our program
int main(int argc, char **argv) {

	const unsigned char *packet;
	struct pcap_pkthdr header;

        char errbuf[PCAP_ERRBUF_SIZE];          /* error buffer */
        pcap_t *handle;                         /* packet capture handle */

        char filter_exp[] = "ip";               /* filter expression [3] */
        struct bpf_program fp;                  /* compiled filter program (expression) */

        print_app_banner();

	if ((argc > 2)||(argc == 1)){
                fprintf(stderr, "error: unrecognized command-line options\n\n");
                print_app_usage();
                exit(EXIT_FAILURE);
        }
	
	handle = pcap_open_offline(argv[1], errbuf);   //call pcap library function	

	if (handle == NULL) {
		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
		return(2);
	}
	else {
		fprintf(stdout,"File %s opened successfully\n", argv[1]);
	}

	fprintf(stdout,"\n");

	while ((packet = pcap_next(handle, &header)) != NULL)
		got_packet(NULL, &header, packet);

	process_sessions();
return 0;
}

