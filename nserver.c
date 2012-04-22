#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "dnsfunctions.h"

//#define ROOT_SERVER_IP "198.41.0.4"
#define ROOT_SERVER_IP "172.24.2.71"
#define ROOT_SERVER "a.root-servers.net"
#define DNS_SERVER "172.24.2.71"

char hostcache[100][100];
char ipcache[100][20];
// Next Free Index
int nfi = 0;
int maxi = 0;

union longchar {
  unsigned char a[5];
  long p;
};
typedef union longchar lchar;

char* checkCache(char*);
void addToCache(char*,char*);
void handleDNSRequest(int);
char* get_nameserver(ghreply,char*);
void print_response(ghreply);
unsigned char* buildReply(unsigned short,
                          unsigned short,
                          unsigned char*,
                          ghreply,
                          unsigned int*);

int main(int argc, char const *argv[])
{
  int sock;
  fd_set rset;
  // Construct the server address structure
  struct addrinfo addrCriteria;                   // Criteria for address
  memset(&addrCriteria, 0, sizeof(addrCriteria)); // Zero out structure
  addrCriteria.ai_family = AF_UNSPEC;             // Any address family
  addrCriteria.ai_flags = AI_PASSIVE;             // Accept on any address/port
  addrCriteria.ai_socktype = SOCK_DGRAM;          // Only datagram socket
  addrCriteria.ai_protocol = IPPROTO_UDP;         // Only UDP socket

  struct addrinfo *servAddr; // List of server addresses
  int rtnVal = getaddrinfo(NULL, "53", &addrCriteria, &servAddr);
  if (rtnVal != 0)
  {
    perror("getaddrinfo() failed");
    exit(1);
  }
  // Create socket for incoming connections
  if((sock = socket(servAddr->ai_family, servAddr->ai_socktype, servAddr->ai_protocol)) < 0)
  {
    perror("socket() failed");
    exit(1);
  }

  // Bind to the local address
  if (bind(sock, servAddr->ai_addr, servAddr->ai_addrlen) < 0)
  {
    perror("bind() failed");
    exit(1);
  }

  // Free address list allocated by getaddrinfo()
  freeaddrinfo(servAddr);

  FD_ZERO(&rset);
  FD_SET(sock, &rset);
  while(1) {
    select(sock + 1, &rset, NULL, NULL, NULL);

    if(FD_ISSET(sock, &rset)) {
      handleDNSRequest(sock);
    }
  }
}
char* checkCache(char * hostname) {
  int i;
  for(i=maxi-1;i>=0;i--) {
    if(strncmp(hostname,hostcache[i],100) == 0) {
      return ipcache[i];
    }
  }
  return NULL;
}
void addToCache(char* hostname,char* ip) {
  strncpy(hostcache[nfi],hostname,100);
  strncpy(ipcache[nfi],ip,20);
  if(nfi < 99) {
    nfi++;
  }
  else {
    nfi = 0;
  }
  if(maxi < 99) {
    maxi++;
  }
}

unsigned char* buildReply(unsigned short reqid,
                          unsigned short rcode,
                          unsigned char* host,
                          ghreply res,
                          unsigned int* replysize) {
  unsigned char rbuf[65536], *qname, *writer;
  struct DNS_HEADER *dns = NULL;
  struct QUESTION *qinfo = NULL;
  struct RES_RECORD *answer,*auth;
  lchar lc;
  int i;

  dns = (struct DNS_HEADER *)&rbuf;
  dns->id = reqid;
  dns->qr = 1;
  dns->opcode = 0;
  dns->aa = 0;
  dns->tc = 0;
  dns->rd = 1;
  dns->ra = 1;
  dns->z = 0;
  dns->ad = 0;
  dns->cd = 0;

  dns->rcode = rcode;
  dns->q_count = htons(1);
  dns->ans_count = htons(res.ans_count);
  dns->auth_count = htons(res.auth_count);
  dns->add_count = htons(res.add_count);

  qname =(unsigned char*)&rbuf[sizeof(struct DNS_HEADER)];
  printf("Answer type: %d\n",ntohs(res.answers[0].resource->type));
  ChangetoDnsNameFormat(qname, host);
  qinfo =(struct QUESTION*)&rbuf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
  qinfo->qtype = htons( T_A );
  qinfo->qclass = htons(1);
  writer = &rbuf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
  *replysize = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);

  for(i=0; i<res.ans_count; i++) {
    printf("Answer type: %d\n",ntohs(res.answers[i].resource->type));
    //if(ntohs(res.answers[i].resource->type) == T_A) {
      answer = (struct RES_RECORD*)malloc(sizeof(struct RES_RECORD));
      printf("Name: %s\n",res.answers[i].name);
      ChangetoDnsNameFormat(writer, res.answers[i].name);
      writer = writer + strlen((const char*)res.answers[i].name)+1;
      *replysize += strlen((const char*)res.answers[i].name)+1;

      answer->resource = (struct R_DATA*)(writer);
      answer->resource->type = htons(1);
      answer->resource->data_len = htons(4);
      answer->resource->ttl = htonl(1800);
      answer->resource->_class = htons(1);
      writer = writer + sizeof(struct R_DATA);
      replysize += sizeof(struct R_DATA);

      writer[0] = res.answers[i].rdata[0];
      writer[1] = res.answers[i].rdata[1];
      writer[2] = res.answers[i].rdata[2];
      writer[3] = res.answers[i].rdata[3];
      writer = writer + 4;
      replysize += 4;
    //}
    //else {
    //  res.ans_count--;
    //}
  }
  
  return rbuf;
}

void handleDNSRequest(int sock) {
  unsigned char buf[65536],*qname, *reader, *host, *rbuf;
  unsigned short reqid, qcount, rcode;
  unsigned int replysize = 0;
  struct DNS_HEADER *dns = NULL;
  int stop = 0, recursion_desired;
  ghreply res;
  struct in_addr *addr;
  char dns_server[20];

  struct sockaddr_storage clntAddr;
  socklen_t clntAddrLen = sizeof(clntAddr);
  addr = (struct in_addr*)malloc(sizeof(struct in_addr));

  if(recvfrom(sock,(char*)buf , 65536, 0, (struct sockaddr*)&clntAddr, &clntAddrLen) < 0) {
    perror("recvfrom");
  }
  dns = (struct DNS_HEADER*) buf;

  if(dns->qr != 0) {
    // not a query!
    return;
  }
  reader = &buf[sizeof(struct DNS_HEADER)];
  // information about request
  host = ReadName(reader,buf,&stop);
  recursion_desired = dns->rd;
  reqid = dns->id;
  qcount = ntohs(dns->q_count);

  // more than 1 question in a query
  if(qcount > 1) {
    // Not Implemented
    rcode = 4;
  }
  // check cache for hostname
  else if((rbuf = checkCache(host)) != NULL) {}
  else if(recursion_desired) {
    strncpy(dns_server,ROOT_SERVER_IP,20);
    while(1) {
      res = ngethostbyname(host,dns_server,1);
      if(res.rcode == 0) {
        if(res.ans_count == 0) {
          //print_response(res);
          strncpy(dns_server,get_nameserver(res,dns_server),20);
        }
        else {
          break;
        }
      }
      else {
        // some error
        break;
      }
    }
    //print_response(res);
    rbuf = buildReply(reqid,rcode,host,res,&replysize);
  }
  if(sendto(sock,(char*)rbuf, replysize, 0, (struct sockaddr*)&clntAddr,clntAddrLen) < 0) {
    perror("sendto failed");
  }
}

char* get_nameserver(ghreply res, char* dns_server) {
  char *nsip;
  nsip = (char*)malloc(sizeof(char)*20);
  char nsdomain[100];
  int i, flag;
  struct sockaddr_in a;
  ghreply tmp;

  flag = 0;
  if(res.add_count > 0) {
    for(i=0; i<res.add_count; i++) {
      if(ntohs(res.addit[i].resource->type)==1) {
        long *p;
        p=(long*)res.addit[i].rdata;
        a.sin_addr.s_addr=(*p);
        strncpy(nsip, inet_ntoa(a.sin_addr),20);
        flag = 1;
        break;
      }
    }
  }
  if(flag == 0) {
    for(i=0; i<res.auth_count; i++) {
      if(ntohs(res.auth[i].resource->type)==2) {
        strncpy(nsdomain,res.auth[i].rdata,100);
        tmp = ngethostbyname(nsdomain,dns_server,1);
        if(tmp.rcode == 0) {
          for(i=0; i<tmp.ans_count; i++) {
            if(ntohs(tmp.answers[i].resource->type) == T_A) {
              long *p;
              p=(long*)tmp.answers[i].rdata;
              a.sin_addr.s_addr=(*p);
              strncpy(nsip,inet_ntoa(a.sin_addr),20);
              flag = 1;
              break;
            }
          }
        }
        break;
      }
    }
  }
  if(flag == 0) {
    printf("Can't find domain. No answer.\n");
    exit(1);
  }
  return nsip;
}
void print_response(ghreply res) {
  int i;
  struct sockaddr_in a;
  switch(res.rcode) {
    case 0:
      break;
    case 3:
      printf("\nNXDOMAIN: server can't find domain\n");
      break;
    default:
      printf("\nSome error\n");
      break;
  }
  printf("\nThe response contains : ");
  printf("\n %d Questions.",res.q_count);
  printf("\n %d Answers.",res.ans_count);
  printf("\n %d Authoritative Servers.",res.auth_count);
  printf("\n %d Additional records.\n",res.add_count);
  //print answers
  printf("\nAnswer Records : %d \n" , res.ans_count);
  for(i=0; i<res.ans_count; i++) {
    printf("Name : %s ",res.answers[i].name);

    if( ntohs(res.answers[i].resource->type) == T_A) {
      long *p;
      p=(long*)res.answers[i].rdata;
      a.sin_addr.s_addr=(*p);
      printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
    }

    if(ntohs(res.answers[i].resource->type)==5) {
      //Canonical name for an alias
      printf("has alias name : %s",res.answers[i].rdata);
    }
    printf("\n");
  }

  //print authorities
  printf("\nAuthoritive Records : %d \n" , res.auth_count);
  for(i=0; i<res.auth_count; i++) {
    printf("Name : %s ",res.auth[i].name);
    if(ntohs(res.auth[i].resource->type)==2) {
      printf("has nameserver : %s",res.auth[i].rdata);
    }
    printf("\n");
  }

  //print additional resource records
  printf("\nAdditional Records : %d \n" , res.add_count);
  for(i=0; i<res.add_count; i++) {
    printf("Name : %s ",res.addit[i].name);
    if(ntohs(res.addit[i].resource->type)==1) {
      long *p;
      p=(long*)res.addit[i].rdata;
      a.sin_addr.s_addr=(*p);
      printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
    }
    printf("\n");
  }
}