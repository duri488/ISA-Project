#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <resolv.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

int isValidIpAddressOrHost(char* IpAddress);
void DNSInfo(char* Domain);
void DNSrecord(char* IPorHost, int NS,char* Name);
char* IPtoHostName(char *IPorHost);
char* IPtoHostName6(char* IPorHost);
int hostname_to_ip(char*, char*);
int whois_query(char* server, char* query, char** response);
void get_whois(char* ip, char* whois);

#define BUFF_SIZE 4096

//global variables
char node[NI_MAXHOST]; //global variable which hold hostname
int isHostname = 0; //flag if we are working in hostname section
int reverseFlag = 0; //flag to check how many times we call get_whois function



int main(int argc, char *argv[])
{

	int option,answ,answWhois;
	int flagQ, flaqW = 0;
	char* IPorHost;
	char* HostName;
	char* Whois;
	char IPwhois[100];

	//loop for parsing arguments
	while ((option = getopt(argc,argv,":q:w:")) != -1 )
	{
		switch (option)
		{
		case 'q':
			flagQ = 1;
			IPorHost = optarg;
			break;
		case 'w':
			flaqW = 1;
			Whois = optarg;
			break;
		case ':':
			printf("All options need value\n");
			printf("Try: ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz\n");
			return 1;
			break;
		case '?':
			printf("Unknown option %c\n", optopt);
			printf("Try: ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz\n");
			return 1;
			break;
		default:
			printf("Unknown error\n");
			printf("Try: ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz\n");
			return 1;
			break;
		}
	}

	//both arguments -q and -w are entered 
	if (flagQ == 1 && flaqW == 1)
	{
		//return 4 if entered value is IPv4, 6 if value is IPv6 or 0 for Hostname
		answ = isValidIpAddressOrHost(IPorHost); 

		if (answ == 4)//if we have IPv4
		{

			//we need Hostname for getting DNS record
			HostName = IPtoHostName(IPorHost);
			
			if (HostName != 0)
			{
				printf("\n******DNS******\n\n");

				DNSInfo(HostName);
				
				printf("\n*****WHOIS*****");
				
				//whois part
				answWhois = isValidIpAddressOrHost(Whois);
				
				//we need IP for connecting to whois and getting answer(answ == 4)
				if (answWhois == 4 || answWhois == 6) //if we have IP
				{
					
					printf(" IP: %s \t WHOIS_IP: %s \n\n", IPorHost, Whois);
					
					get_whois(IPorHost, Whois);
				}
				else //if we have Hostname
				{
					
					//getting IP from Whois value Hostname
					if (hostname_to_ip(Whois, IPwhois) == 1)
					{
						printf("\n\nError: Couldn't find IP for Hostname: %s\n", Whois);
						//printf("Unknown error\n");
						//printf("Try: ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz\n");
						return 1;
					}
					else
					{
						printf(" IP: %s \t WHOIS_IP: %s \n\n", IPorHost, IPwhois);

						get_whois(IPorHost, IPwhois);

					}

				}
			}

		}
		else 
		{
			if (answ == 6) //if we have IPv6
			{
				//we need Hostname for getting DNS record
				HostName = IPtoHostName6(IPorHost);
				if (HostName != 0)
				{
					printf("\n******DNS******\n\n");

					DNSInfo(HostName);

					printf("\n*****WHOIS*****");
				}

				//whois part
				answWhois = isValidIpAddressOrHost(Whois);

				//we need IP for connecting to whois and getting answer(answ == 6)
				if (answWhois == 4 || answWhois == 6) //if we have IP
				{
					printf(" IP: %s \t WHOIS_IP: %s \n\n", IPorHost, Whois);

					get_whois(IPorHost, Whois);
				}
				else //if we have Hostname
				{
					//getting IP from Whois value Hostname
					if (hostname_to_ip(Whois, IPwhois) == 1)
					{
						printf("\n\nError: Couldn't find IP for Hostname: %s\n", Whois);
						//printf("Unknown error\n");
						//printf("Try: ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz\n");
						return 1;
					}
					else
					{
						printf(" IP: %s \t WHOIS_IP: %s \n\n", IPorHost, IPwhois);

						get_whois(IPorHost, IPwhois);

						return 0;
					}
				}
			}
			else //if we have Hostname
			{
				//we have Hostname for getting DNS record
				printf("\n******DNS******\n\n");

				isHostname = 1;
				DNSInfo(IPorHost);

				//whois part

				printf("\n*****WHOIS*****");
				
					answWhois = isValidIpAddressOrHost(Whois);

					//we need IP for connecting to whois
					if (answWhois == 4 || answWhois == 6) //if we have IP
					{
						printf(" IP: %s \t WHOIS_IP: %s \n\n", IPorHost, Whois);
						get_whois(IPorHost, Whois);
					}
					else //if we have Hostname
					{
						if (hostname_to_ip(Whois, IPwhois) == 1)
						{
							printf("\n\nError: Couldn't find IP for Hostname: %s\n", Whois);
							//printf("Unknown error\n");
							//printf("Try: ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz\n");
							return 1;
						}						
						else
						{
							printf(" IP: %s \t WHOIS_IP: %s \n\n",IPorHost,IPwhois);

							get_whois(IPorHost, IPwhois);

							return 0;
						}
					}
				
			}
		}
	}
	else
	{
		printf("Wrong arguments\n");
		printf("Try: ./isa-tazatel -w whois.ripe.net -q www.fit.vutbr.cz\n");		
		return 1;
	}
	return 0;
}

/*********************************************************FUNCTIONS*********************************************************/



/*********************************************************************************
*
*	Source for function: hostname_to_ip
*
*	Title: Get ip address from hostname in C using Linux sockets
*	Author: Silver Moon
*	Availability: https://www.binarytides.com/hostname-to-ip-address-c-sockets-linux/
*
*********************************************************************************/

int hostname_to_ip(char* hostname, char* ip) //function that convert hostname to IP
{
	struct hostent* he;
	struct in_addr** addr_list;
	int i;

	//if succes save IP to "he" struct
	if ((he = gethostbyname(hostname)) == NULL)
	{
		
		return 1;
	}

	addr_list = (struct in_addr**) he -> h_addr_list;

	//loop for copy ip to variable
	for (i = 0; addr_list[i] != NULL; i++)
	{
		strcpy(ip, inet_ntoa(*addr_list[i]));
		return 0;
	}

	return 1;
}



int isValidIpAddressOrHost(char* IpAddress) //function check if input is IPv4(return 4), IPv6(return 6) or Hostname(return 0)
{
	struct sockaddr_in sa;
	struct sockaddr_in6 sa6;
	
	if (inet_pton(AF_INET, IpAddress, &(sa.sin_addr)))
	{
		return 4;
	}
	else 
	{
		if (inet_pton(AF_INET6, IpAddress, &(sa6.sin6_addr)))
		{
			return 6;
		}
	}
	return 0;
}



/*********************************************************************************
*
*	Source for function: DNSrecord
*
*	Title: How to query a server and get the MX, A, NS records
*	Author: Dima00782
*	Availability: https://stackoverflow.com/questions/15476717/how-to-query-a-server-and-get-the-mx-a-ns-records
*
*********************************************************************************/

void DNSrecord(char* IPorHost,int NS, char* Name) {
	
	u_char nsbuf[BUFF_SIZE];
	char dispbuf[BUFF_SIZE];
	char tmpDispbuf[BUFF_SIZE];
	ns_msg msg;
	ns_rr rr;
	int i, l;

	//getting DNS record for type NS
	l = res_query(IPorHost, ns_c_in, NS, nsbuf, sizeof(nsbuf));
	if (l < 0)
	{
		//if there is no record we print no info msg
		//special case is PTR where we are getting record by IP
		if (!strcmp(Name, "PTR"))
		{
			if (isHostname != 1)
			{
				printf("%s:	        ", Name);
				printf("%s\n", IPorHost);
			}			
		}
		else
		{
			printf("Couldn't find info about %s\n", Name);
		}			
	}
	else
	{
		//parsing answer 
		ns_initparse(nsbuf, l, &msg);
		l = ns_msg_count(msg, ns_s_an);

		//MX and SOA records require special parsing
		for (i = 0; i < l; i++)
		{
			ns_parserr(&msg, ns_s_an, i, &rr);
			ns_sprintrr(&msg, &rr, NULL, NULL, dispbuf, sizeof(dispbuf));

			//MX record parsing
			if (!strcmp(Name,"MX")) {

				printf("%s:	       ", Name);

				//we use last occurrence of the character(if there is tab we do it 3times else 2 times)
				if (strrchr(strrchr(strrchr(dispbuf, ' '), ' '),'\t') == NULL)
				{
					printf("%s\n", strrchr(strrchr(dispbuf, ' '), ' '));
				}
				else
				{
					printf("%s\n", strrchr(strrchr(strrchr(dispbuf, ' '), ' '), '\t'));
				}
			}
			else
			{
				char* rest = NULL;
				char* tmp = NULL;
				char* token;
				char* res;
						
				//SOA record parsing
				if (!strcmp(Name, "SOA"))
				{
					strcpy(tmpDispbuf, dispbuf);
					printf("%s:	      ", Name);

					//we split answers into tokens by diferent delimiter to get answer
					//sometimes answer is not IN type part but IN CNAME part
					token = strtok_r(tmpDispbuf, "E", &rest);
					token = strtok_r(tmpDispbuf, "C", &rest);

					if (!strcmp(rest, "NAM"))
					{
						token = strtok_r(dispbuf, "E", &rest);
						printf("%s\n", rest);
						continue;
					}
					else//answer is IN type part
					{
						token = strtok_r(dispbuf, "(", &rest);
						token = strtok_r(dispbuf, "A", &rest);
						token = strtok_r(rest, " ", &tmp);
						printf("%s\n", rest);

						//getting admin info and changing "@" for "." 
						printf("ADMIN:	        ");
						token = strtok_r(tmp, ".", &rest);
						printf("%s@%s\n",tmp,rest);
						continue;
					}					
				}

				//other answers parsing

				strcpy(tmpDispbuf,dispbuf);

				//we split answers into tokens by diferent delimiter to get answer
				//sometimes answer is not IN type part but IN CNAME part

				token = strtok_r(tmpDispbuf, "E", &rest);
				token = strtok_r(tmpDispbuf, "C", &rest);
				if (!strcmp(rest,"NAM")) //answer is not IN type part but IN CNAME part
				{
					rest = NULL;
					//getting last token from line 
					for (token = strtok_r(dispbuf, "E", &rest); token != NULL; token = strtok_r(NULL, "E", &rest))
					{
						res = token;
					}
					printf("%s:	      ", Name);
					printf("%s\n", res);
				}
				else //answer is IN type part
				{
					rest = NULL;
					//getting last token from line 
					for (token = strtok_r(dispbuf, Name, &rest); token != NULL; token = strtok_r(NULL, Name, &rest))
					{
						res = token;
					}
					printf("%s:	      ", Name);
					printf("%s\n", res);
				}				
			}
		}
	}
}



/*********************************************************************************
*
*	Source for function: IPtoHostName/IPtoHostName6
*
*	Title: getnameinfo() example problem
*	Author: algorism
*	Availability: https://cboard.cprogramming.com/c-programming/169902-getnameinfo-example-problem.html
*
*********************************************************************************/

char* IPtoHostName(char* IPorHost)
{
	struct sockaddr_in sa;
	int test;
	//preparing structure
	memset(&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	test = inet_pton(AF_INET, IPorHost, &sa.sin_addr); //checking if IPv4 is correct

	if (test != 1)
	{
		printf("Invalid IP address\n");
		return 0;
	}
	//getting hostname
	int res = getnameinfo((struct sockaddr*) & sa, sizeof(sa),node, sizeof(node), NULL, 0, NI_NAMEREQD);

	if (res) 
	{
		printf("Option -q: %s\n", gai_strerror(res));
		return 0;
	}
	else
	{
		//returning hostname
		return node;
	}
}

char* IPtoHostName6(char* IPorHost)
{
	struct sockaddr_in6 sa6;
	int test;
	//preparing structure
	memset(&sa6, 0, sizeof sa6);
	sa6.sin6_family = AF_INET6;
	test = inet_pton(AF_INET6, IPorHost, &sa6.sin6_addr); //checking if IPv6 is correct

	if (test != 1)
	{
		printf("Invalid IP address\n");
		return 0;
	}
	//getting hostname
	int res = getnameinfo((struct sockaddr*) & sa6, sizeof(sa6), node, sizeof(node), NULL, 0, NI_NAMEREQD);

	if (res)
	{
		printf("Option -q: %s\n", gai_strerror(res));
		return 0;
	}
	else
	{
		//returning hostname
		return node;
	}
}

void DNSInfo(char* Domain)
{
	//getting DNS info for different types
	DNSrecord(Domain, ns_t_a, "A");
	DNSrecord(Domain, ns_t_aaaa, "AAAA");
	DNSrecord(Domain, ns_t_mx, "MX");
	DNSrecord(Domain, ns_t_ns, "NS");
	DNSrecord(Domain, ns_t_soa, "SOA");
	DNSrecord(Domain, ns_t_ptr, "PTR");
	DNSrecord(Domain, ns_t_cname, "CNAME");
}



/*********************************************************************************
*
*	Source for function: whois_query/get_whois
*
*	Title: C code to perform IP whois
*	Author: Silver Moon
*	Availability: https://www.binarytides.com/c-code-to-perform-ip-whois/?fbclid=IwAR16bvD_my3KWkeyT5FfAJaJdniwAqv6GrMJR5vk3I22SMq4ri77Pjas1FQ
*
*********************************************************************************/

int whois_query(char* server, char* query, char** response)
{
	char message[100], buffer[1500];
	int sock, read_size, total_size = 0;
	struct sockaddr_in dest;
	struct sockaddr_in6 dest6;

	if (isValidIpAddressOrHost(query) == 4)
	{
		//preparing socket
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		//prepare connection structures 
		memset(&dest, 0, sizeof(dest));
		dest.sin_family = AF_INET;

		dest.sin_addr.s_addr = inet_addr(query);
		dest.sin_port = htons(43);

		//connecting to query(whois)
		if (connect(sock, (const struct sockaddr*) & dest, sizeof(dest)) < 0)
		{
			perror("connect failed");
		}
	}
	else
	{
		//preparing socket
		sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);

		//prepare connection structures 
		memset(&dest6, 0, sizeof(dest6));
		dest6.sin6_family = AF_INET6;

		inet_pton(AF_INET6, query, &dest6.sin6_addr.s6_addr);
		dest6.sin6_port = htons(43);

		//connecting to query(whois)
		if (connect(sock, (const struct sockaddr*) & dest6, sizeof(dest6)) < 0)
		{
			perror("connect failed");
		}
	}

	//Now send some data or message(IP for which we wanna get whois info)
	sprintf(message, "%s\r\n", server);
	if (send(sock, message, strlen(message), 0) < 0)
	{
		perror("send failed");
	}

	//receive the response
	while ((read_size = recv(sock, buffer, sizeof(buffer), 0)))
	{
		*response = realloc(*response, read_size + total_size);
		if (*response == NULL)
		{
			printf("realloc failed");
		}
		memcpy(*response + total_size, buffer, read_size);
		total_size += read_size;
	}

	*response = realloc(*response, total_size + 1);
	*(*response + total_size) = '\0';

	//closing connection
	close(sock);
	return 0;
}

void get_whois(char* ip, char* whois)
{
	char * response = NULL, lookIP[100], * wch = NULL, * pch;
	int flag = 0;
	whois_query(ip, whois, &response);
	//parsing answer from whois
	pch = strtok(response, "\n");

	while (pch != NULL)
	{
		//Check if whois line
		wch = strstr(pch, "whois.");
		if (wch != NULL)
		{
			break;
		}
		//looking for specific data
		if (strncmp(pch, "inetnum:", 8) == 0 || strncmp(pch, "inet6num:", 8) == 0 || strncmp(pch, "netname:", 8) == 0 || strncmp(pch, "descr:", 6) == 0
		||	strncmp(pch, "country:", 8) == 0 || strncmp(pch, "address:", 8) == 0 || strncmp(pch, "phone:", 6) == 0
		|| strncmp(pch, "admin-c:", 8) == 0  )
		{
			printf("%s\n", pch);
			flag = 1;
		}
		else
		{		
			//if there is some error and we don't find anything
			if (strncmp(pch, "%ERROR:101:", 11) == 0)
			{
				
				//we will try recursive query
				int answw;
				answw = isValidIpAddressOrHost(ip);
				
				//for IPv4
				if (answw == 4)
				{
					//we get hostname from IPv4
					if (IPtoHostName(ip) == 0)
					{
						printf("WHOIS: Data not found for: %s \n", ip);
						printf("WHOIS: Couldn't find IP for Hostname: %s \n\n", ip);
						printf("WHOIS: Not found any data \n");
						return;
					}
					else
					{
						//we try it only once
						if (reverseFlag != 1)
						{
							printf("WHOIS: data not found for: %s \n", ip);
							printf("WHOIS: Trying: %s \n\n", node);
							//we call recursive function with hostname
							reverseFlag += 1;
							get_whois(node, whois);
							return;
						}

					}
				}
				else
				{
					//for IPv6
					if (answw == 6)
					{
						//we get hostname from IPv6
						if (IPtoHostName6(ip) == 0)
						{
							printf("WHOIS: Data not found for: %s \n", ip);
							printf("WHOIS: Couldn't find IP for Hostname: %s \n\n", ip);
							printf("WHOIS: Not found any data \n");
							return;
						}
						else
						{
							//we try it only once
							if (reverseFlag != 1)
							{
								printf("WHOIS: data not found for: %s \n", ip);
								printf("WHOIS: Trying: %s \n\n", node);								
								//we call recursive function with hostname
								reverseFlag += 1;							
								get_whois(node, whois);
								return;
							}

						}

					}
					else
					{
						//for hostname
						//we get IPv4 from hostname
						if (hostname_to_ip(ip, lookIP) == 1)
						{
							printf("WHOIS: Data not found for: %s \n", ip);
							printf("WHOIS: Couldn't find IP for Hostname: %s \n\n", ip);
							printf("WHOIS: Not found any data \n");
							return;
						}
						else
						{
							//we try it only once
							if (reverseFlag != 1)
							{
								printf("WHOIS: data not found for: %s \n", ip);
								printf("WHOIS: Trying: %s \n\n", lookIP);
								//we call recursive function with IPv4
								reverseFlag += 1;
								get_whois(lookIP, whois);
								return;
							}
						}						
					}
				}
			}
		}

		//Next line 
		pch = strtok(NULL, "\n");
	}
	//if found nothing
	if (flag == 0) 
	{
		printf("WHOIS: Not found any data \n");
	}
	return;
}