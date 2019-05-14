/*
 * Copyright GPL by Robert Olsson roolss@kth.se/robert@radio-sensors.com
 * Created : 2017-02-09
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <signal.h>

#define VERSION "1.7 2019-01-10"
#define BUFLEN 512

#define PORT 5683
unsigned short port = PORT;

int file_fd;
#define LOGFILE "./coap.dat"

#define PS_DISCOVERY "/.well-known/core?rt=core.ps"
#define DISCOVERY "/.well-known/core"

#define D_COAP_PKT      (1<<0)
#define D_COAP_REPORT   (1<<1)
#define D_COAP_STRING   (1<<2)

#define BROKER_BASE_URI "<ps/>;rt=core.ps;ct=40"
char *broker_base_uri = BROKER_BASE_URI;
char *host  = NULL;

#define MAX_URI_LEN 50
char uri[MAX_URI_LEN];

char *server   = NULL;
char *sub_uri   = NULL;
char *get_uri   = NULL;
char *pub_uri   = NULL;
char *crt_uri   = NULL;
char *payload   = NULL;
char *dis_uri   = NULL;

/* CoAP types */
typedef enum {
  COAP_TYPE_CON,         /* confirm*/
  COAP_TYPE_NON,         /* non-confirm */
  COAP_TYPE_ACK,         /* ack */
  COAP_TYPE_RST          /* reset */
} coap_type_t;

/* CoAP requests */
typedef enum {
  COAP_GET = 1,
  COAP_POST,
  COAP_PUT,
  COAP_DELETE
  } coap_request_t;

/* CoAP responses */
typedef enum {
  NO_ERROR = 0,
  CREATED_2_01 = 65,
  DELETED_2_02 = 66,
  VALID_2_03 = 67,
  CHANGED_2_04 = 68,
  CONTENT_2_05 = 69,
  CONTINUE_2_31 = 95,
  BAD_REQUEST_4_00 = 128,
  UNAUTHORIZED_4_01 = 129,
  BAD_OPTION_4_02 = 130,
  FORBIDDEN_4_03 = 131,
  NOT_FOUND_4_04 = 132,
  METHOD_NOT_ALLOWED_4_05 = 133,
  NOT_ACCEPTABLE_4_06 = 134,
  PRECONDITION_FAILED_4_12 = 140,
  REQUEST_ENTITY_TOO_LARGE_4_13 = 141,
  UNSUPPORTED_MEDIA_TYPE_4_15 = 143,
  INTERNAL_SERVER_ERROR_5_00 = 160,
  NOT_IMPLEMENTED_5_01 = 161,
  BAD_GATEWAY_5_02 = 162,
  SERVICE_UNAVAILABLE_5_03 = 163,
  GATEWAY_TIMEOUT_5_04 = 164,
  PROXYING_NOT_SUPPORTED_5_05 = 165,
} coap_response_t;

/* CoAP options */
typedef enum {
  COAP_OPTION_IF_MATCH = 1,     /* 0-8 B */
  COAP_OPTION_URI_HOST = 3,     /* 1-255 B */
  COAP_OPTION_ETAG = 4,         /* 1-8 B */
  COAP_OPTION_IF_NONE_MATCH = 5,        /* 0 B */
  COAP_OPTION_OBSERVE = 6,      /* 0-3 B */
  COAP_OPTION_URI_PORT = 7,     /* 0-2 B */
  COAP_OPTION_LOCATION_PATH = 8,        /* 0-255 B */
  COAP_OPTION_URI_PATH = 11,    /* 0-255 B */
  COAP_OPTION_CONTENT_FORMAT = 12,      /* 0-2 B */
  COAP_OPTION_MAX_AGE = 14,     /* 0-4 B */
  COAP_OPTION_URI_QUERY = 15,   /* 0-255 B */
  COAP_OPTION_ACCEPT = 17,      /* 0-2 B */
  COAP_OPTION_LOCATION_QUERY = 20,      /* 0-255 B */
  COAP_OPTION_BLOCK2 = 23,      /* 1-3 B */
  COAP_OPTION_BLOCK1 = 27,      /* 1-3 B */
  COAP_OPTION_SIZE2 = 28,       /* 0-4 B */
  COAP_OPTION_PROXY_URI = 35,   /* 1-1034 B */
  COAP_OPTION_PROXY_SCHEME = 39,        /* 1-255 B */
  COAP_OPTION_SIZE1 = 60,       /* 0-4 B */
} coap_option_t;

/* CoAP content formats */
typedef enum {
  CONTENT_NOT_DEFINED = -1,
  TEXT_PLAIN = 0,
  TEXT_XML = 1,
  TEXT_CSV = 2,
  TEXT_HTML = 3,
  IMAGE_GIF = 21,
  IMAGE_JPEG = 22,
  IMAGE_PNG = 23,
  IMAGE_TIFF = 24,
  AUDIO_RAW = 25,
  VIDEO_RAW = 26,
  APPLICATION_LINK_FORMAT = 40,
  APPLICATION_XML = 41,
  APPLICATION_OCTET_STREAM = 42,
  APPLICATION_RDF_XML = 43,
  APPLICATION_SOAP_XML = 44,
  APPLICATION_ATOM_XML = 45,
  APPLICATION_XMPP_XML = 46,
  APPLICATION_EXI = 47,
  APPLICATION_FASTINFOSET = 48,
  APPLICATION_SOAP_FASTINFOSET = 49,
  APPLICATION_JSON = 50,
  APPLICATION_X_OBIX_BINARY = 51
} coap_content_t;

unsigned int debug = 0;
int date = 1, utime =0, gmt=0, background = 0;
int ct = TEXT_PLAIN;
int32_t max_age = 60; /* We use default */

struct udp_hdr {
 unsigned short int sport;
 unsigned short int dport;/* default mode */
 unsigned short int len;
 unsigned short int csum;
};

struct coap_hdr {
  unsigned char tkl:4;
  unsigned char type:2;
  unsigned char ver:2;
  unsigned char code:8;
  unsigned short id;
};

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Ver| T |  TKL  |      Code     |          Message ID           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Token (if any, TKL bytes) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Options (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1 1 1 1 1 1 1 1|    Payload (if any) ...
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                Figure 7: Message Format from RFC 8323
*/

/* Token handling */
#define MAX_TOKEN_LEN 8
unsigned char tok[MAX_TOKEN_LEN];

/* Option handling */
struct coap_opt_s {
  unsigned int len:4;
  unsigned int delta:4;
};

/* Option handling */
struct coap_opt_l {
  unsigned int flag:4;  /* either 15 or 13 depending on the CoAP version */
  unsigned int delta:4; /* option type (expressed as delta) */
  unsigned int len:8;   /* MAX_URI_LEN = 50 so one byte is enough for extended length */
};

char *response(int code)
{
  char *r;

  switch(code) {

    case  NO_ERROR : r = "NO_ERROR";  break;
    case  CREATED_2_01 : r = "CREATED_2_01";  break;
    case  DELETED_2_02 : r = "DELETED_2_02";  break;
    case  VALID_2_03 : r = "VALID_2_03";  break;
    case  CHANGED_2_04 : r = "CHANGED_2_04";  break;
    case  CONTENT_2_05 : r = "CONTENT_2_05";  break;
    case  CONTINUE_2_31 : r = "CONTINUE_2_31";  break;
    case  BAD_REQUEST_4_00 : r = "BAD_REQUEST_4_00";  break;
    case  UNAUTHORIZED_4_01 : r = "UNAUTHORIZED_4_01";  break;
    case  BAD_OPTION_4_02 : r = "BAD_OPTION_4_02";  break;
    case  FORBIDDEN_4_03 : r = "FORBIDDEN_4_03";  break;
    case  NOT_FOUND_4_04 : r = "NOT_FOUND_4_04";  break;
    case  METHOD_NOT_ALLOWED_4_05: r = "METHOD_NOT_ALLOWED_4_05";  break;
    case  NOT_ACCEPTABLE_4_06 : r = "NOT_ACCEPTABLE_4_06";  break;
    case  PRECONDITION_FAILED_4_12 : r = "PRECONDITION_FAILED_4_12";  break;
    case  REQUEST_ENTITY_TOO_LARGE_4_13 : r = "REQUEST_ENTITY_TOO_LARGE_4_13";  break;
    case  UNSUPPORTED_MEDIA_TYPE_4_15 : r = "UNSUPPORTED_MEDIA_TYPE_4_15";  break;
    case  INTERNAL_SERVER_ERROR_5_00 : r = "INTERNAL_SERVER_ERROR_5_00";  break;
    case  NOT_IMPLEMENTED_5_01 : r = "NOT_IMPLEMENTED_5_01";  break;
    case  BAD_GATEWAY_5_02 : r = "BAD_GATEWAY_5_02";  break;
    case  SERVICE_UNAVAILABLE_5_03  : r = "SERVICE_UNAVAILABLE_5_03";  break;
    case  GATEWAY_TIMEOUT_5_04 : r = "GATEWAY_TIMEOUT_5_04";  break;
    case  PROXYING_NOT_SUPPORTED_5_05 : r = "PROXYING_NOT_SUPPORTED_5_05";  break;
    default:
      r = "UNKNOWN";
  }
  return r;
}

void usage(void)
{
  printf("\nVersion %s\n", VERSION);
  printf("\ncoap: A CoAP pubsub server/endpoint\n");
  printf("  * Also a simple CoAP pubsub application\n");
  printf("  * Timestamps and logs pubsub data in file\n");
  printf("  * Verbose protocol and option debugging\n");
  printf("  * Implementation in plain C, no libs, no classes etc\n");
  printf("  * GPL copyright\n");
  printf("\ncoap [-d] [-b] [-p port] [-gmt] [-f file] [-cf type] [-ma time] [-dis host uri] [-sub host uri] [-pub host uri payload]\n");
  printf(" -f file        -- local logfile. Default is %s\n", LOGFILE);
  printf(" -p port        -- TCP server port. Default %d\n", port);
  printf(" -b             -- run in background\n");
  printf(" -d             -- debug\n");
  printf(" -ut            -- add Unix time\n");
  printf(" -gmt           -- time in GMT\n");
  printf(" -ct  type      -- content format\n");
  printf(" -ma  time      -- max age in sec\n");
  printf(" -dis host uri  -- discover\n");
  printf(" -sub host uri  -- subscribe\n");
  printf(" -pub host uri  -- publish\n");
  printf(" -get host uri  -- get\n");

  printf("\nExample 1 -- coap discover:\n coap -dis 192.16.125.232 .well-known/core\n");
  printf("\nExample 2 -- pubsub discover:\n coap -dis 192.16.125.232 .well-known/core?rt=core.ps\n");
  printf("\nExample 3 -- subscribe a topic:\n coap -sub 192.16.125.232  ps/fcc23d0000017f97/topic1\n");
  printf("\nExample 4 -- publish on a topic:\n coap -pub 192.16.125.232  ps/fcc23d0000017f97/topic1 200\n");
  printf("\nExample 5 -- subscribe a topic output stdout:\n coap -f - -sub 192.16.125.232  ps/fcc23d0000017f97/topic1\n");
  printf("\nExample 6 -- get a topic:\n coap -get 192.16.125.232  ps/fcc23d0000017f97/topic1\n");
  printf("\nExample 7 -- server:\n coap\n");

  exit(-1);
}

void print_date(char *datebuf)
{
  time_t raw_time;
  struct tm *tp;
  char buf[256];

  *datebuf = 0;
  time ( &raw_time );

  if(gmt)
    tp = gmtime ( &raw_time );
  else
    tp = localtime ( &raw_time );

  if(date) {
	  sprintf(buf, "%04d-%02d-%02d %2d:%02d:%02d ",
		  tp->tm_year+1900, tp->tm_mon+1,
		  tp->tm_mday, tp->tm_hour,
		  tp->tm_min, tp->tm_sec);
	  strcat(datebuf, buf);
  }
  if(utime) {
	  sprintf(buf, "UT=%ld ", raw_time);
	  strcat(datebuf, buf);
  }
}

void dump_pkt(struct coap_hdr *ch, int len, char *info)
{
  int i;
  unsigned char *d = (unsigned char *) ch;
  unsigned ii, opt = 0, old_opt = 0;

  printf("DUMP at %s HEAD lengh=%d\n", info, len);

  printf(" Hex:\n");
  for(i = 0; i < len; i++) {
    if(!i)
      printf("[%3d]", i);

    printf(" %02x", d[i] & 0xFF);

    if(! ((i+1)%16) )
      printf("\n[%3d]", i);
  }
  printf("\n");


  printf(" v=%u t=%u tkl=%u code=%u id=%x\n", ch->ver, ch->type, ch->tkl, ch->code, ch->id);

  printf(" Token TKL=%d", ch->tkl);
  for(i = 0; i < ch->tkl; i++) {
    printf(" %02x ", d[i+4] & 0xFF);
  }
  printf("\n");


  for(i = 4 + (ch->tkl); i < len; i++) {
    unsigned olen;

    /* Option delta handling */
    opt = (d[i]>>4) & 0xF;

    if(opt > 12 ) {
      if(opt == 13) {
        i++;
        opt = d[i] + 13;
      }
      else if(opt == 14) {
        printf("UNTESTED OPT 14\n");
        i++;
        opt = d[i]<<8;
        i++;
        opt += d[i];
        opt += 269;
      }
      else if(opt == 15) {
        printf(" Payload: ");
        printf("%s\n", &d[i+1]);
        break; //return;
      }
    }
    opt += old_opt;

    olen = (d[i]) & 0xF;
    if(olen > 12 ) {
      if(olen == 13) {
        i++;
        olen = d[i] + 13;
      }
      else if(olen == 14) {
        printf("UNTESTED OLEN 14\n");
        i++;
        olen = d[i]<<8;
        i++;
        olen += d[i];
        olen += 269;
      }
      else if(olen == 15) {
	      printf("ERR OPT FORMAT LEN=15\n");
      }
    }

    printf(" Option: opt=%u, len=%u ", opt, olen);

    if( 1 ) {
      if(opt == COAP_OPTION_URI_PATH) {
        printf("uri-path=");
        for(ii = 1; ii <= olen; ii++)
          printf("%c", d[ii+i]);
      }
      else if(opt == COAP_OPTION_CONTENT_FORMAT) {
        printf("content-format=");
        for(ii = 1; ii <= olen; ii++)
          printf("0x%02x", d[ii+i]);
      }
      else if(opt == COAP_OPTION_URI_QUERY) {
        printf("uri-query=");
        for(ii = 1; ii <= olen; ii++)
          printf("%c", d[ii+i]);
      }
      else if(opt == COAP_OPTION_OBSERVE) {
        printf("observe=");
        for(ii = 1; ii <= olen; ii++)
          printf("0x%02x", d[ii+i]);
      }
      else if(opt == COAP_OPTION_CONTENT_FORMAT) {
        printf("cf=%d", d[i+1]);
      }
      else if(opt == COAP_OPTION_MAX_AGE) {
        if(olen == 1)
          printf("Max-Age=%u", (unsigned char) (d[i+1]));
        else if(olen == 2)
          printf("Max-Age=%u", ((uint32_t) ((uint32_t)d[i+1])<<8) + (unsigned char) d[i+2]);
        else if(olen == 3)
          printf("Max-Age=%u", ((uint32_t) ((uint32_t)d[i+1])<<16)  + (((uint32_t)d[i+2])<<8) + (unsigned char) d[i+3]);
      }
    }
    printf("\n");

    old_opt = opt;
    i = i + olen;
  }
  printf("DUMP END\n");
}

void parse_subscribe(struct coap_hdr *ch, int len, char *p)
{
  int i;
  char *d = (char *) ch;
  unsigned opt = 0, old_opt = 0;

  for(i = 4 + (ch->tkl); i < len; i++) {
    unsigned olen;

    /* Option delta handling */
    opt = (d[i]>>4) & 0xF;

    if(opt > 12 ) {
      if(opt == 13) {
        i++;
        opt = d[i] + 13;
      }
      else if(opt == 14) {
        printf("PS UNTESTED OPT 14\n");
        i++;
        opt = d[i]<<8;
        i++;
        opt += d[i];
        opt += 269;
      }
      else if(opt == 15) {
        *p++ = ' ';
        strncpy(p, &d[i+1], strlen(&d[i+1]));
        return;
      }
    }
    opt += old_opt;

    olen = (d[i]) & 0xF;
    if(olen > 12 ) {
      if(olen == 13) {
        i++;
        olen = d[i] + 13;
      }
      else if(olen == 14) {
        printf("PS UNTESTED OLEN 14\n");
        i++;
        olen = d[i]<<8;
        i++;
        olen += d[i];
        olen += 269;
      }
      else if(olen == 15) {
	      printf("PS ERR OPT FORMAT LEN=15\n");
      }
    }

    if( olen ) {
      if(opt == COAP_OPTION_URI_PATH) {
        unsigned ii;
        for(ii = 1; ii <= olen; ii++)
          *p++ =  d[ii+i];
      }
      else if(opt == COAP_OPTION_URI_QUERY) {
      unsigned ii;
      for(ii = 1; ii <= olen; ii++)
            *p++ =  d[ii+i];
            *p++ = ' ';
          }
          old_opt = opt;
          i = i + olen;
    }
  }
}

void terminate(char *s)
{
    perror(s);
    exit(1);
}

int do_packet(char *buf, unsigned char type, unsigned char code, char *uri,
	      char *uri_query, int content, char *payload, unsigned char tkl, unsigned char *tok,
	      unsigned char obsl, unsigned obsv)
{
  int len = 0;

  struct coap_hdr *ch_tx;
  struct coap_opt_s *ch_os;
  struct coap_opt_l *ch_ol;

  ch_tx = (struct coap_hdr*) &buf[0];
  len = sizeof(struct coap_hdr);
  int last_option=0;

  ch_tx->ver = 1;
  ch_tx->type = type;
  ch_tx->tkl = tkl;
  ch_tx->code = code;
  ch_tx->id = rand() %1000;


  if(tkl > MAX_TOKEN_LEN) {
    terminate("CoAP token length err");
  }

  if(tkl) {
    memcpy(&buf[4], tok, tkl);
	  len += tkl;
  }

  if( obsl ) {
    ch_os = (struct coap_opt_s*) &buf[len];
    ch_os->delta = COAP_OPTION_OBSERVE - last_option; /* COAP_OPTION_OBSERVE */
    last_option = COAP_OPTION_OBSERVE;
    ch_os->len = obsl;
    len++;
    buf[len] = obsv;
    len += obsl;
  }

  if( uri ) {
    if(strlen(uri) <= 12) {
      ch_os = (struct coap_opt_s*) &buf[len];
      ch_os->delta = COAP_OPTION_URI_PATH - last_option; /* COAP_OPTION_URI_PATH = 11 */
      last_option = COAP_OPTION_URI_PATH;
      ch_os->len = strlen(uri);
      len++;
      strcpy(&buf[len], uri); /* Short opt */
      len += strlen(uri);
    }
    else if(strlen(uri) > 12) {
      ch_ol = (struct coap_opt_l*) &buf[len];
      ch_ol->delta = COAP_OPTION_URI_PATH - last_option; /* COAP_OPTION_URI_PATH = 11 */
      last_option = COAP_OPTION_URI_PATH;
      ch_ol->flag = 13;   /* 1 byte extension */
      ch_ol->len = strlen(uri) - 13;
      len += 2;
      strcpy(&buf[len], uri); /* Long opt */
      len += strlen(uri);
      if(debug & D_COAP_PKT)
	      printf("LONG delta flg=%d , delta=%d, len=%d\n", ch_ol->flag, ch_ol->delta, ch_ol->len);
    }
  }

  if(content != CONTENT_NOT_DEFINED) {
    ch_os = (struct coap_opt_s*) &buf[len];
    ch_os->delta = COAP_OPTION_CONTENT_FORMAT - last_option; /* COAP_OPTION_CONTENT_FORMAT = 12 */
    last_option = COAP_OPTION_CONTENT_FORMAT;
    ch_os->len = 1;
    len++;
    buf[len] = content;
    len++;
  }

  if(pub_uri || crt_uri) {
    ch_os = (struct coap_opt_s*) &buf[len];
    ch_os->delta = COAP_OPTION_MAX_AGE - last_option; /* COAP_OPTION_MAX_AGE = 14 */
    last_option = COAP_OPTION_MAX_AGE;
    if(max_age <= 255) {
      ch_os->len = 1;
      len++;
      buf[len] = (unsigned char) max_age & 0xFF;
      len++;
    }
    else if(max_age <= 65536) {
      ch_os->len = 2;
      len++;
      buf[len] = (unsigned char) (max_age>>8);
      len++;
      buf[len] = (unsigned char) max_age & 0xFF;
      len++;
    }
    else {
      ch_os->len = 3;
      len++;
      buf[len] = (unsigned char) (max_age>>16);
      len++;
      buf[len] = (unsigned char) (max_age>>8);
      len++;
      buf[len] = (unsigned char) max_age & 0xFF;
      len++;
    }
  }

  if(uri_query) {
    ch_os = (struct coap_opt_s*) &buf[len];
    ch_os->delta = COAP_OPTION_URI_QUERY  - last_option; /* COAP_OPTION_URI_QUERY = 15 */
    last_option = COAP_OPTION_URI_QUERY;
    ch_os->len = strlen(uri_query);
    len++;
    strcpy(&buf[len], uri_query); /* Short opt */
    len += strlen(uri_query);
  }

  if(payload) {
    buf[len] = 0xff;
    len++;
    if(crt_uri){
      char *pl;
      asprintf(&pl,"%s%s%s","<",payload,">;ct=40");
      strcpy(&buf[len], pl);
      len += strlen(pl);
    }
    else{
      strcpy(&buf[len], payload);
      len += strlen(payload);
    }
  }

  return len;
}

int process(void)
{

    struct sockaddr_in si_me, si_other;
    int s , recv_len, send_len, init = 0;
    socklen_t slen = sizeof(si_other);
    unsigned char i, tkl;
    char buf[BUFLEN], p[BUFLEN];
    struct coap_hdr *co;
    //char *discover = "</ps/>;rt=core.ps";
    char *discover = "</ps/>";

    if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)  {
        terminate("socket");
    }

    if(server) {
      memset((char *) &si_me, 0, sizeof(si_me));
      si_me.sin_family = AF_INET;
      si_me.sin_port = htons(port);
      si_me.sin_addr.s_addr = htonl(INADDR_ANY);
      if( bind(s , (struct sockaddr*)&si_me, sizeof(si_me) ) == -1) {
	      terminate("bind");
      }
    }
    else if(dis_uri) {
      si_other.sin_family = AF_INET;
      si_other.sin_port = htons(port);
      if (inet_aton(host , &si_other.sin_addr) == 0) {
	      terminate("inet_aton");
      }

      for (i = 0; i < MAX_TOKEN_LEN; i++)
        tok[i] = rand();
      tkl = 2;
      send_len = do_packet(buf, COAP_TYPE_CON, COAP_GET, dis_uri, NULL, CONTENT_NOT_DEFINED, NULL, tkl, tok, 0,0);
      if(send_len) {
        if(debug & D_COAP_PKT)
          dump_pkt((struct coap_hdr*)buf, send_len, "dis");

        if (sendto(s, buf, send_len, 0, (struct sockaddr*) &si_other, slen) == -1)  {
          terminate("sendto()");
        }
        if(debug & D_COAP_PKT)
          printf("Sent %d bytes to %s:%d\n", send_len, inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));
      }
    }
    else if(pub_uri) {
      si_other.sin_family = AF_INET;
      si_other.sin_port = htons(port);
      if (inet_aton(host , &si_other.sin_addr) == 0) {
	      terminate("inet_aton");
      }

      for (i = 0; i < MAX_TOKEN_LEN; i++)
        tok[i] = rand();
      tkl = 2;
      send_len = do_packet(buf, COAP_TYPE_CON, COAP_PUT, pub_uri, NULL, ct, payload, tkl, tok, 0,0);
      if(send_len) {
        if(debug & D_COAP_PKT)
          dump_pkt((struct coap_hdr*)buf, send_len, "pub");

        if (sendto(s, buf, send_len, 0, (struct sockaddr*) &si_other,
            slen) == -1)  {
          terminate("sendto()");
        }
        if(debug & D_COAP_PKT)
          printf("Sent %d bytes to %s:%d\n", send_len, inet_ntoa(si_other.sin_addr),
          ntohs(si_other.sin_port));
      }
    }
    else if(crt_uri) {

      si_other.sin_family = AF_INET;
      si_other.sin_port = htons(port);

      if (inet_aton(host , &si_other.sin_addr) == 0) {
	      terminate("inet_aton");
      }

      for (i = 0; i < MAX_TOKEN_LEN; i++)
        tok[i] = rand();
      tkl = 2;

      send_len = do_packet(buf, COAP_TYPE_CON, COAP_POST, crt_uri, NULL, ct, payload, tkl, tok, 0,0);

      if(send_len) {
        if(debug & D_COAP_PKT)
	        dump_pkt((struct coap_hdr*)buf, send_len, "pub");

        if (sendto(s, buf, send_len, 0, (struct sockaddr*) &si_other, slen) == -1)  {
	        terminate("sendto()");
	      }

        if(debug & D_COAP_PKT)
          printf("Sent %d bytes to %s:%d\n", send_len, inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

      }

    }
    else if(sub_uri) {
      si_other.sin_family = AF_INET;
      si_other.sin_port = htons(port);
      if (inet_aton(host , &si_other.sin_addr) == 0) {
	      terminate("inet_aton");
      }

      for (i = 0; i < MAX_TOKEN_LEN; i++)
	      tok[i] = rand();
      tkl = 2;
      send_len = do_packet(buf, COAP_TYPE_CON, COAP_GET, sub_uri, NULL, TEXT_PLAIN, NULL, tkl, tok, 1,0);

      if(send_len) {
        if(debug & D_COAP_PKT)
          dump_pkt((struct coap_hdr*)buf, send_len, "sub");

        if (sendto(s, buf, send_len, 0, (struct sockaddr*) &si_other, slen) == -1)  {
          terminate("sendto()");
        }
      }
    }
    else if(get_uri) {
      si_other.sin_family = AF_INET;
      si_other.sin_port = htons(port);
      if (inet_aton(host , &si_other.sin_addr) == 0) {
	      terminate("inet_aton");
      }

      for (i = 0; i < MAX_TOKEN_LEN; i++)
	      tok[i] = rand();
      tkl = 2;
      send_len = do_packet(buf, COAP_TYPE_CON, COAP_GET, get_uri, NULL, TEXT_PLAIN, NULL, tkl, tok, 0,0);

      if(send_len) {
        if(debug & D_COAP_PKT)
          dump_pkt((struct coap_hdr*)buf, send_len, "get");

        if (sendto(s, buf, send_len, 0, (struct sockaddr*) &si_other, slen) == -1)  {
          terminate("sendto()");
        }
      }
    }

    while(1)
    {
      memset((char *) &buf, 0, sizeof(buf));
      send_len = 0;

      if ((recv_len = recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &si_other, &slen)) == -1) {
	      terminate("recvfrom()");
      }

      if(debug & D_COAP_PKT)
	      printf("Got %d bytes from %s:%d\n", recv_len, inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

      co = (struct coap_hdr*) &buf[0];

      if(debug & D_COAP_PKT)
	      dump_pkt(co, recv_len, "recv");

      if(co->ver != 1) {
	      terminate("CoAP version err");
      }

      if(co->tkl > MAX_TOKEN_LEN) {
	      terminate("CoAP token length err");
      }

      if(co->tkl)
      	memcpy(tok, &buf[4], co->tkl);


      if(co->type == COAP_TYPE_ACK)
      	printf("%s %d\n", response(co->code), co->code);


      /* Simple CoAP pubsub state machinery */

      /* DISCOVER reply*/
      if((co->type == COAP_TYPE_CON) && (co->code == COAP_GET)) {
        send_len = do_packet(buf, COAP_TYPE_ACK, CONTENT_2_05, discover, NULL, APPLICATION_LINK_FORMAT,
                broker_base_uri, co->tkl, tok,0,0);
      }

      if(sub_uri || get_uri)
	      init = 1;

      /* CREATE reply */
      if((co->type == COAP_TYPE_CON) && (co->code == COAP_POST)) {
        send_len = do_packet(buf, COAP_TYPE_ACK, CREATED_2_01, NULL, NULL, CONTENT_NOT_DEFINED, NULL, co->tkl, tok,0,0);
        init = 1;
      }

      /* SUBSCRIBE -- PUT OR POST reply */
      if(get_uri || sub_uri || ((co->type == COAP_TYPE_CON) && (co->code == COAP_PUT))) {
        memset((char *) &p, 0, sizeof(p));

        if(init == 0) {
          send_len = do_packet(buf, COAP_TYPE_RST, CHANGED_2_04, NULL, NULL, CONTENT_NOT_DEFINED, NULL, co->tkl, tok,0,0);
          continue;
        }

        print_date(p);
        if(file_fd)
          write(file_fd, p, strlen(p));
        if(!background)
          printf("%s", p);
        memset((char *) &p, 0, sizeof(p));

        parse_subscribe(co, recv_len, p);
        p[strlen(p)] = '\n';

        if(file_fd)
          write(file_fd, p, strlen(p));

        if(!background)
          printf("%s", p);

        if(! sub_uri)
          send_len = do_packet(buf, COAP_TYPE_ACK, CHANGED_2_04, NULL, NULL, CONTENT_NOT_DEFINED, NULL, co->tkl, tok,0,0);
      }

      if(send_len) {
        if(debug & D_COAP_PKT)
          dump_pkt(co, send_len, "ack");

        if (sendto(s, buf, send_len, 0, (struct sockaddr*) &si_other, slen) == -1)  {
          terminate("sendto()");
        }
        if(debug & D_COAP_PKT)
          printf("Sent %d bytes to %s:%d\n", send_len, inet_ntoa(si_other.sin_addr), ntohs(si_other.sin_port));

        if(get_uri)
          break;
      }

      /* Parse discovery respone */
      if(dis_uri) {
        print_date(p);
        if(file_fd)
          write(file_fd, p, strlen(p));
        if(!background)
          printf("%s", p);
        memset((char *) &p, 0, sizeof(p));

        parse_subscribe(co, recv_len, p);
        p[strlen(p)] = '\n';

        if(file_fd)
          write(file_fd, p, strlen(p));

        if(!background)
          printf("%s", p);
        break;
      }

      /* pub respone */
      if(pub_uri) {
	      break;
      }
    }
    close(s);
    return 0;
}

int main(int ac, char *av[])
{
  int i;
  char *filename = LOGFILE;

  for(i = 1; (i < ac) && (av[i][0] == '-'); i++)  {

    if (strncmp(av[i], "-gmt", 3) == 0)
      gmt = 1;
    else if (strncmp(av[i], "-h", 2) == 0)
      usage();
    else if (strncmp(av[i], "-ct", 3) == 0)
      ct = atoi(av[i++]);
    else if (strncmp(av[i], "-ut", 3) == 0)
      utime = 1;
    else if (strncmp(av[i], "-f", 2) == 0)
      filename = av[++i];
    else if (strncmp(av[i], "-ma", 3) == 0)
      max_age = atoi(av[++i]);
    else if (strncmp(av[i], "-dis", 4) == 0) {
      host = av[++i];
      dis_uri = av[++i];
    }
    else if (strncmp(av[i], "-d", 2) == 0)
      debug = 3;
    else if (strncmp(av[i], "-pub", 4) == 0) {
      host = av[++i];
      pub_uri = av[++i];
      payload = av[++i];
    }
    else if (strncmp(av[i], "-crt", 4) == 0) {
      host = av[++i];
      crt_uri = av[++i];
      payload = av[++i];
    }
    else if (strncmp(av[i], "-get", 4) == 0) {
      host = av[++i];
      get_uri = av[++i];
    }
    else if (strncmp(av[i], "-sub", 4) == 0) {
      host = av[++i];
      sub_uri = av[++i];
    }
    else if (strncmp(av[i], "-server", 7) == 0) {
    }
    else if (strncmp(av[i], "-p", 2) == 0)
      port = atoi(av[++i]);
    else if (strncmp(av[i], "-b", 2) == 0)
      background = 1;
  }

  if(!sub_uri && !pub_uri && !dis_uri && !get_uri && !crt_uri)
    server = "enabled\n";


  /* Setup for some radom */
  srand((unsigned int)**main + (unsigned int)&ac + (unsigned int)time(NULL));
  srand(rand());

  if(debug) {
    printf("DEBUG host=%s\n", host);
    printf("DEBUG port=%d\n", port);
    printf("DEBUG GMT=%d\n", gmt);
    printf("DEBUG Unix Time=%d\n", utime);
    printf("DEBUG background=%d\n", background);
    printf("DEBUG file=%s\n", filename);
    printf("DEBUG ct=%d\n", ct);
    printf("DEBUG max_age=%d\n", max_age);
    printf("DEBUG dis_uri=%s\n", dis_uri);
    printf("DEBUG sub_uri=%s\n", sub_uri);
    printf("DEBUG pub_uri=%s\n", pub_uri);
    printf("DEBUG crt_uri=%s\n", crt_uri);
    printf("DEBUG get_uri=%s\n", get_uri);
  }

  if(filename) {
    file_fd = open(filename, O_CREAT|O_RDWR|O_APPEND, 0644);
    if(file_fd < 0) {
      fprintf(stderr, "Failed to open '%s'\n", filename);
      exit(2);
    }
  }

  if(background) {
    int i;
    if(getppid() == 1)
      return 0; /* Already a daemon */

    i = fork();

    if (i < 0)
      exit(1); /* error */

    if (i > 0)
      _exit(0); /* parent exits */

    setsid(); /* obtain a new process group */
    for (i = getdtablesize(); i >= 0; --i) {
      if(i == file_fd) continue;
      if(debug && i == 1) continue;
      close(i); /* close all descriptors */
    }

    i = open("/dev/null",O_RDWR); dup(i); dup(i); /* handle standard I/O */
    umask(027); /* set newly created file permissions */
    chdir("/"); /* change running directory */

    signal(SIGCHLD,SIG_IGN); /* ignore child */
  }
  process();
  return 0;
}
