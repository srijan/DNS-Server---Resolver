#include "ndns.h"

struct gethost_reply {
  unsigned char rcode;
  unsigned short q_count;
  unsigned short ans_count;
  unsigned short auth_count;
  unsigned short add_count;

  struct RES_RECORD answers[20];
  struct RES_RECORD auth[20];
  struct RES_RECORD addit[20];
};
typedef struct gethost_reply ghreply;
ghreply ngethostbyname(unsigned char *, unsigned char *, int);
void ChangetoDnsNameFormat (unsigned char*,unsigned char*);
unsigned char* ReadName (unsigned char*,unsigned char*,int*);
