#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
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

void handleDNSRequest(int sock) {
  unsigned char buf[65536],*qname, *writer, hname[20], *host;
  unsigned short reqid, qcount;
  unsigned int replysize = 0;
  struct DNS_HEADER *dns = NULL;
  struct QUESTION *qinfo = NULL;
  struct RES_RECORD *answer,*auth;
  int stop = 0, recursion_desired;
  char *ip;
  lchar lc;
  ghreply hostdetails, tmphd;
  struct in_addr *addr;

  struct sockaddr_storage clntAddr;
  socklen_t clntAddrLen = sizeof(clntAddr);
  addr = (struct in_addr*)malloc(sizeof(struct in_addr));

  if(recvfrom(sock,(char*)buf , 65536, 0, (struct sockaddr*)&clntAddr, &clntAddrLen) < 0) {
    perror("recvfrom");
  }
  dns = (struct DNS_HEADER*) buf;

  if(dns->qr != 0) {
    return;
  }
  writer = &buf[sizeof(struct DNS_HEADER)];
  // information about request
  host = ReadName(writer,buf,&stop);
  recursion_desired = dns->rd;
  reqid = dns->id;
  qcount = ntohs(dns->q_count);

  // preparing response
  bzero(buf,sizeof(buf));
  dns = (struct DNS_HEADER *)&buf;
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

  dns->rcode = 0;
  // 0 - NoError
  // 3 - NXDomain
  // 4 - NotImp

  dns->q_count = htons(1);
  dns->ans_count = htons(0);
  dns->auth_count = htons(0);
  dns->add_count = htons(0);

  qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
  ChangetoDnsNameFormat(qname , host);
  host[strlen(host)-1] = '\0';
  qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname) + 1)];
  qinfo->qtype = htons( T_A );
  qinfo->qclass = htons(1);
  writer = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
  replysize = sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION);

  if(qcount != 1) {
    dns->rcode = 4;
  }
  else if((ip = checkCache(host)) != NULL) {        // check cache for hostname
    printf("Host %s found in cache.\n",host);
    dns->rcode = 0;   // NoError
    dns->ans_count = htons(1);
  }
  else if(recursion_desired) {
    hostdetails = ngethostbyname(host, ROOT_SERVER_IP, 1, 0);
    host[strlen(host)-1] = '\0';
    while(hostdetails.type == 1) {
      tmphd = ngethostbyname(hostdetails.details, DNS_SERVER, 1, 0);
      if(tmphd.type == -1) {
        // Not Found
        // Serious Error
        dns->rcode = 2;
      }
      else {
        hostdetails = ngethostbyname(host, tmphd.details, 1, 0);
        host[strlen(host)-1] = '\0';
      }
    }
    if(dns->rcode != 2) {
      if(hostdetails.type == -1) {
        printf("Host %s not found.\n",host);
        ip = NULL;
        dns->rcode = 3; // NXDomain
      }
      else {
        printf("Host %s found using root server.\n",host);
        ip = (char*)malloc(sizeof(char)*20);
        strncpy(ip,hostdetails.details,20);
      }
    }
  }
  else {
    // iterative
    dns->rcode = 0;
    dns->ans_count = htons(0);
    dns->auth_count = htons(1);
    dns->add_count = htons(0);

    auth = (struct RES_RECORD*)malloc(sizeof(struct RES_RECORD));
    strcpy(writer,qname);
    writer = writer + strlen((const char*)qname)+1;
    replysize += strlen((const char*)qname)+1;

    auth->resource = (struct R_DATA*)(writer);
    auth->resource->type = htons(2);
    auth->resource->data_len = htons(strlen(ROOT_SERVER));
    auth->resource->ttl = htonl(146016);
    auth->resource->_class = htons(1);
    writer = writer + sizeof(struct R_DATA);
    replysize += sizeof(struct R_DATA);

    strcpy(writer," ");
    writer = writer + 1;
    replysize++;
    strcpy(writer,ROOT_SERVER);
    writer = writer + strlen(ROOT_SERVER);
    replysize += strlen(ROOT_SERVER);
  }
  if(ip != NULL) {
    // add to cache
    addToCache(host,ip);

    dns->rcode = 0;
    dns->ans_count = htons(1);
    dns->auth_count = htons(0);
    dns->add_count = htons(0);

    answer = (struct RES_RECORD*)malloc(sizeof(struct RES_RECORD));
    strcpy(writer,qname);
    writer = writer + strlen((const char*)qname)+1;
    replysize += strlen((const char*)qname)+1;

    answer->resource = (struct R_DATA*)(writer);
    answer->resource->type = htons(1);
    answer->resource->data_len = htons(4);
    answer->resource->ttl = htonl(1800);
    answer->resource->_class = htons(1);
    writer = writer + sizeof(struct R_DATA);
    replysize += sizeof(struct R_DATA);

    inet_aton(ip,addr);
    lc.p = addr->s_addr;
    writer[0] = lc.a[0];
    writer[1] = lc.a[1];
    writer[2] = lc.a[2];
    writer[3] = lc.a[3];
    writer = writer + 4;
    replysize += 4;
  }
  if(sendto(sock,(char*)buf, replysize, 0, (struct sockaddr*)&clntAddr,clntAddrLen) < 0) {
    perror("sendto failed");
  }
}
