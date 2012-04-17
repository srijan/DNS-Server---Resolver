#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include "dnsfunctions.h"

ghreply ngethostbyname(unsigned char *host,unsigned char *dns_server, int recursion_desired, int print_messages) {
  unsigned char buf[65536],*qname,*reader;
  int i , j , stop , s;
  struct sockaddr_in a;
  struct RES_RECORD answers[20],auth[20],addit[20]; //the replies from the DNS server
  struct sockaddr_in dest;

  struct DNS_HEADER *dns = NULL;
  struct QUESTION *qinfo = NULL;

  ghreply retval;
  retval.type = -2;

  if(print_messages)
    printf("Resolving %s using %s" , host, dns_server);

  s = socket(AF_INET , SOCK_DGRAM , IPPROTO_UDP); //UDP packet for DNS queries

  dest.sin_family = AF_INET;
  dest.sin_port = htons(53);
  dest.sin_addr.s_addr = inet_addr(dns_server); //dns server

  //Set the DNS structure to standard queries
  dns = (struct DNS_HEADER *)&buf;

  dns->id = (unsigned short) htons(getpid());
  dns->qr = 0; //This is a query
  dns->opcode = 0; //This is a standard query
  dns->aa = 0; //Not Authoritative
  dns->tc = 0; //This message is not truncated
  dns->rd = recursion_desired; //Recursion Desired
  dns->ra = 0;
  dns->z = 0;
  dns->ad = 0;
  dns->cd = 0;
  dns->rcode = 0;
  dns->q_count = htons(1); //we have only 1 question
  dns->ans_count = 0;
  dns->auth_count = 0;
  dns->add_count = 0;

  //point to the query portion
  qname =(unsigned char*)&buf[sizeof(struct DNS_HEADER)];
  ChangetoDnsNameFormat(qname , host);
  qinfo =(struct QUESTION*)&buf[sizeof(struct DNS_HEADER) 
    + (strlen((const char*)qname) + 1)]; //fill it

  qinfo->qtype = htons( T_A ); // sending query of A record type
  qinfo->qclass = htons(1); //its internet

  if(sendto(s,(char*)buf,sizeof(struct DNS_HEADER)
        + (strlen((const char*)qname)+1)
        + sizeof(struct QUESTION),0,(struct sockaddr*)&dest,sizeof(dest))
      < 0) {
    perror("sendto failed");
  }

  //Receive the answer
  i = sizeof dest;
  if(recvfrom(s,(char*)buf , 65536, 0, (struct sockaddr*)&dest, (socklen_t*)&i)
      < 0) {
    perror("recvfrom failed");
  }
  dns = (struct DNS_HEADER*) buf;

  //move ahead of the dns header and the query field
  reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];

  if(print_messages) {
    printf("\nThe response contains : ");
    printf("\n %d Questions.",ntohs(dns->q_count));
    printf("\n %d Answers.",ntohs(dns->ans_count));
    printf("\n %d Authoritative Servers.",ntohs(dns->auth_count));
    printf("\n %d Additional records.\n",ntohs(dns->add_count));
  }

  if(recursion_desired && !dns->q_count) {
    retval.type = -1;
  }

  //Start reading answers
  reader = &buf[sizeof(struct DNS_HEADER) + (strlen((const char*)qname)+1) + sizeof(struct QUESTION)];
  stop=0;

  for(i=0;i<ntohs(dns->ans_count);i++)
  {
    answers[i].name=ReadName(reader,buf,&stop);
    reader = reader + stop;

    answers[i].resource = (struct R_DATA*)(reader);
    reader = reader + sizeof(struct R_DATA);

    if(ntohs(answers[i].resource->type) == 1) //if its an ipv4 address
    {
      answers[i].rdata = (unsigned char*)malloc(ntohs(answers[i].resource->data_len));

      for(j=0 ; j<ntohs(answers[i].resource->data_len) ; j++)
      {
        answers[i].rdata[j]=reader[j];
      }

      answers[i].rdata[ntohs(answers[i].resource->data_len)] = '\0';

      reader = reader + ntohs(answers[i].resource->data_len);
    }
    else
    {
      answers[i].rdata = ReadName(reader,buf,&stop);
      reader = reader + stop;
    }
  }

  //read authorities
  for(i=0;i<ntohs(dns->auth_count);i++)
  {
    auth[i].name=ReadName(reader,buf,&stop);
    reader+=stop;

    auth[i].resource=(struct R_DATA*)(reader);
    reader+=sizeof(struct R_DATA);

    auth[i].rdata=ReadName(reader,buf,&stop);
    reader+=stop;
  }

  //read additional
  for(i=0;i<ntohs(dns->add_count);i++)
  {
    addit[i].name=ReadName(reader,buf,&stop);
    reader+=stop;

    addit[i].resource=(struct R_DATA*)(reader);
    reader+=sizeof(struct R_DATA);

    if(ntohs(addit[i].resource->type)==1)
    {
      addit[i].rdata = (unsigned char*)malloc(ntohs(addit[i].resource->data_len));
      for(j=0;j<ntohs(addit[i].resource->data_len);j++)
        addit[i].rdata[j]=reader[j];

      addit[i].rdata[ntohs(addit[i].resource->data_len)]='\0';
      reader+=ntohs(addit[i].resource->data_len);
    }
    else
    {
      addit[i].rdata=ReadName(reader,buf,&stop);
      reader+=stop;
    }
  }

  //print answers
  if(print_messages)
    printf("\nAnswer Records : %d \n" , ntohs(dns->ans_count) );
  for(i=0 ; i < ntohs(dns->ans_count) ; i++)
  {
    if(print_messages)
      printf("Name : %s ",answers[i].name);

    if( ntohs(answers[i].resource->type) == T_A) //IPv4 address
    {
      long *p;
      p=(long*)answers[i].rdata;
      a.sin_addr.s_addr=(*p); //working without ntohl
      if(print_messages)
        printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
      if(retval.type == -2) {
        retval.type = 0;
        strncpy(retval.details, inet_ntoa(a.sin_addr),100);
      }
    }

    if(ntohs(answers[i].resource->type)==5)
    {
      //Canonical name for an alias
      if(print_messages)
        printf("has alias name : %s",answers[i].rdata);
    }
    if(print_messages)
      printf("\n");
  }

  //print authorities
  if(print_messages)
    printf("\nAuthoritive Records : %d \n" , ntohs(dns->auth_count) );
  for( i=0 ; i < ntohs(dns->auth_count) ; i++)
  {
    if(print_messages)
      printf("Name : %s ",auth[i].name);
    if(ntohs(auth[i].resource->type)==2)
    {
      if(print_messages)
        printf("has nameserver : %s",auth[i].rdata);
      if(retval.type == -2) {
        retval.type = 1;
        strncpy(retval.details,auth[i].rdata,100);
      }
    }
    if(print_messages)
      printf("\n");
  }

  //print additional resource records
  if(print_messages)
    printf("\nAdditional Records : %d \n" , ntohs(dns->add_count) );
  for(i=0; i < ntohs(dns->add_count) ; i++)
  {
    if(print_messages)
      printf("Name : %s ",addit[i].name);
    if(ntohs(addit[i].resource->type)==1)
    {
      long *p;
      p=(long*)addit[i].rdata;
      a.sin_addr.s_addr=(*p);
      if(print_messages)
        printf("has IPv4 address : %s",inet_ntoa(a.sin_addr));
    }
    if(print_messages)
      printf("\n");
  }
  if(retval.type == -2) {
    retval.type = -1;
  }
  return retval;
}

void ChangetoDnsNameFormat(unsigned char* dns,unsigned char* host) {
  int lock = 0 , i;
  strcat((char*)host,".");

  for(i = 0 ; i < strlen((char*)host) ; i++) {
    if(host[i]=='.') {
      *dns++ = i-lock;
      for(;lock<i;lock++) {
        *dns++=host[lock];
      }
      lock++; //or lock=i+1;
    }
  }
  *dns++='\0';
}

u_char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
  unsigned char *name;
  unsigned int p=0,jumped=0,offset;
  int i , j;

  *count = 1;
  name = (unsigned char*)malloc(256);
  name[0]='\0';

  //read the names in 3www6google3com format
  while(*reader!=0) {
    if(*reader>=192) {
      offset = (*reader)*256 + *(reader+1) - 49152; //49152 = 11000000 00000000 ;)
      reader = buffer + offset - 1;
      jumped = 1; //we have jumped to another location so counting wont go up!
    }
    else {
      name[p++]=*reader;
    }
    reader = reader+1;
    if(jumped==0) {
      *count = *count + 1; //if we havent jumped to another location then we can count up
    }
  }
  name[p]='\0'; //string complete
  if(jumped==1) {
    *count = *count + 1; //number of steps we actually moved forward in the packet
  }
  //now convert 3www6google3com0 to www.google.com
  for(i=0;i<(int)strlen((const char*)name);i++) {
    p=name[i];
    for(j=0;j<(int)p;j++) {
      name[i]=name[i+1];
      i=i+1;
    }
    name[i]='.';
  }
  name[i-1]='\0'; //remove the last dot
  return name;
}

