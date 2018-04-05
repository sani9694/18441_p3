/*
 * echoserver.c - A simple connection-based echo server
 * usage: echoserver <port>
 */


#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <sys/time.h>
#include <time.h>
#include <uuid/uuid.h>
#include <mach/clock.h>
#include <mach/mach.h>


#define BUFSIZE 1024
#define MAXLINE 8192
#define SERVLEN 100
#define HOSTLEN 256
#define PACKET_SIZE 1400
#define HEADER 16


#if 0
/*
 * Structs exported from netinet/in.h (for easy reference)
 */

/* Internet address */
struct in_addr {
    unsigned int s_addr;
};

/* Internet style socket address */
struct sockaddr_in  {
    unsigned short int sin_family; /* Address family */
    unsigned short int sin_port;   /* Port number */
    struct in_addr sin_addr;     /* IP address */
    unsigned char sin_zero[...];   /* Pad to size of 'struct sockaddr' */
};

/*
 * Struct exported from netdb.h
 */

/* Domain name service (DNS) host entry */
struct hostent {
    char    *h_name;        /* official name of host */
    char    **h_aliases;    /* alias list */
    int     h_addrtype;     /* host address type */
    int     h_length;       /* length of address */
    char    **h_addr_list;  /* list of addresses */
}
#endif


const char* error404 = "<html><head><title>404 Error: Not Found</title></head><body>404 File Not Found</body></html>";

/* URI parsing results. */
typedef enum {
    PARSE_ERROR,
    PARSE_CORRECT
} parse_result;

/* Peer Functions*/
typedef enum {
    VIEW = 0,
    ADD = 1,
    CONFIG = 2,
    STATUS = 3,
    NONE = 4,
    KILL = 5,
    UUID = 6,
    ADDNEIGHBOR = 7,
    NEIGHBORS = 8
} peer_method;

/* Client Info for Connection Thread*/
typedef struct {
    struct sockaddr_in addr;    // Socket address
    socklen_t addrlen;          // Socket address length
    int connfd;                 // Client connection file descriptor
    char host[HOSTLEN];         // Client host
    char serv[SERVLEN];         // Client service (port)
} client_info;

/* Parsed URI structure */
typedef struct {
    char method[MAXLINE];
    char path[MAXLINE];
    char version;
    char temp[MAXLINE];
    char ext[MAXLINE];
    char host[MAXLINE];
    uuid_t uuid;
    unsigned int back_port;
    unsigned int front_port;
    unsigned int rate;
    unsigned int distance;
    parse_result result;
    peer_method pm;
} url_info;

typedef struct {
    const char *ext;
    char *iana;
} ftype;

ftype file_types [] = {
    {".txt", "text/plain"},
    {".css", "text/css"},
    {".htm", "text/html"},
    {".html", "text/html"},
    {".gif", "image/gif"},
    {".jpeg", "image/jpeg"},
    {".jpg", "image/jpeg"},
    {".ico", "image/x-icon"},
    {".png", "image/png"},
    {".js", "application/javascript"},
    {".ogg", "video/ogg"},
    {".mp4", "video/mp4"},
    {".webm", "video/webm"},
    {".octet-stream","application/octet-stream"},
    {".json", "application/json"},
    {NULL, NULL},
};
int rand_close = 0;
/*Our own custom UDP packet*/
typedef struct {
    char flags;             //byte  0     ASFX  (Ack, Syn, Fin, Unused)
    char pack;              //byte  1 
    uint16_t source_port;   //bytes 2  - 3
    uint16_t dest_port;     //bytes 4  - 5
    uint16_t length;        //bytes 6  - 7
    uint16_t syn;           //bytes 8  - 9
    uint16_t ack;           //bytes 10 - 11
    uint16_t window;        //bytes 12 - 13
    uint16_t rtt;           //bytes 14 - 15
    char* data;             //bytes 16 - (17+length)
} packet;

typedef struct peer{
    uuid_t uuid;
    char* name;
    uint16_t front_port;
    uint16_t back_port;
    char* content_dir;
    int distance;
    int num_files;
    char* files[20];       //Max number of files one peer can have is 20 **** MAYBE REVISIT AND MAKE IT DYNAMICALLY ALLOCATE
    char* host;
    struct sockaddr_in addr;
    int last_sent;
    int last_received;
} peer, *peer_t;

void printPeer(peer_t self)
{
    char* ud = malloc(sizeof(char)*37);
    printf("------------------------Peer: %s---------------------\n", self->name);
    uuid_unparse(self->uuid, ud);
    printf("uuid: %s\n", ud);
    printf("name: %s\n", self->name);
    printf("frontend_port: %u\n", self->front_port);
    printf("backend_port: %u\n", self->back_port);
    printf("content_dir: %s\n", self->content_dir);
    printf("-----------------------------------------------------------\n");
}


peer_t peer_table[100];
static int num_peers = 0;




typedef struct{
    char *filename;
    struct sockaddr_in addr; //client socket address
    unsigned short port;
} New_peer;
//static New_peer new_peer;

/* peer database table*/
New_peer my_db[100];
static int db_entries = 0;

/* newflow struct for flow table */
typedef struct{
    char pack; // ID for the flow
    struct sockaddr_in addr;
    socklen_t addrlen;
    uint16_t base_syn;
    uint16_t syn; //init
    uint16_t nss;
    uint16_t naa;
    uint16_t ack;
    int src_port;
    int last_ack;
    int window_size;
    int last_sent;
    char filename[MAXLINE];
    FILE* file;
    long file_size;
    int client_fd;
    uint16_t window;
    int available;
    uint64_t last_ack_time;
    int error;
    int on_fd;
} New_flow;
//static New_flow new_flow;

/* flow database */
New_flow my_flow[25];
static int flow_entries = 0;


static int back_port;
static int back_fd;
static int window_g = 10; //change accordgingly
static unsigned int max_window_size;
static int rate;


packet* unwrap(char* buf);
char* package(packet* p);
void addPeer(char *file, struct sockaddr_in, unsigned short int s_port);
void flow(char flow_ID, unsigned int s_addr, unsigned short int s_port, uint16_t base_syn, char *file);
packet* request_new_packet(char* path, char flowID, uint16_t source_port, uint16_t dest_port);
char getFlowID();
uint16_t getSequence();
void *serve(int connfd, fd_set* live_set);
char* get_rfc_time();
void re_tx_last(packet* p, New_flow* prev_flow, int fd);
void re_tx_last_sender(packet* p, New_flow* nf, int fd);
struct sockaddr_in get_sockaddr_from_host(char* host, uint16_t back_port);

int getTimeMilliseconds() {
    struct timespec ts;

    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts.tv_sec = mts.tv_sec;
    ts.tv_nsec = mts.tv_nsec;


    uint64_t delta_ms = (ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    return delta_ms;
}

/*
 * error - wrapper for perror
 */
void error(char *msg) {
    perror(msg);
    // exit(1);
}

void printFlowTable()
{
    // printf("~~~~~~~~~~~f l o w      t a b l e~~~~~~~~~~~~~~\n");
    // for(int i = 0; i < flow_entries; i++)
    // {
    //     printf("%d: %s | ", my_flow[i].pack, my_flow[i].filename);
    // }
    // printf("\n~~~~~~~~~~~e n d     t a b l e ~~~~~~~~~~~~~~\n");
}

void printPacket(packet* p)
{
    // printf("------------------------Printing Packet-------------------------------------------\n");
    // printf("flags: %u | flowID: %d | source_port: %u\n", p->flags, (int)p->pack, p->source_port);
    // printf("dest_port: %u | length: %u\n", p->dest_port, p->length);
    // printf("syn: %u | ack: %u\n", p->syn, p->ack);
    // printf("window: %u | rtt: %u\n", p->window, p->rtt);
    // printf("data: %s\n", p->data);
    // printf("-----------------------------End Packet-------------------------------------------\n");

}

char getFlowID()
{
//Random Number Gen
    return (char)(rand()%255);
}

uint16_t getSequence()
{
//Random Number Gen
    return (uint16_t)(rand());
}

void addNeighbor(uuid_t uuid, char* host, uint16_t frontend, uint16_t backend, int distance)
{
    peer_t np = malloc(sizeof(peer));
    uuid_copy(np->uuid, uuid);

    np->host = malloc(sizeof(char)*strlen(host));
    sprintf(np->host, "%s", host);

    np->name = malloc(sizeof(char)*8);
    sprintf(np->name, "peer_%d", (num_peers-1));

    np->back_port = backend;
    np->front_port = frontend;
    np->distance = distance;
    np->content_dir = malloc(sizeof(char)*9);
    np->content_dir = "content/";
    np->num_files = 0;
    np->last_sent = getTimeMilliseconds();
    np->last_received = getTimeMilliseconds();
    peer_table[num_peers] = np;
    np->addr = get_sockaddr_from_host(np->host, np->back_port);
    num_peers++;
}

char* peerToJSON(peer_t p)
{
    char* json = malloc(sizeof(char)*400);
    char uuid[40];
    uuid_unparse(p->uuid, uuid);
    sprintf(json, "{\"uuid\":\"%s\","
                  "\"name\":\"%s\","
                  "\"host\":\"%s\","
                  "\"frontend\":\"%u\","
                  "\"backend\":\"%u\","
                  "\"num_files\":\"%d\","
                  "\"metric\":\"%d\"}", uuid, p->name, p->host, p->front_port, p->back_port, p->num_files, p->distance);
    return json;

}

char* tableToJSON()
{
    char* json = malloc(sizeof(char)*MAXLINE);
    sprintf(json, "[%s", peerToJSON(peer_table[0]));
    for(int i = 1; i < num_peers; i++)
    {
        json = strcat(json, ",");
        json = strcat(json, peerToJSON(peer_table[i]));
    }
    json = strcat(json, "]");
    return json;
}


/* Addpeer: adds the peer address and port to the table */

void addPeer(char *file, struct sockaddr_in serveraddr, unsigned short int s_port){
    
    New_peer* np;
    printf("Adding new peer! %s %d %u\n", file, serveraddr.sin_addr.s_addr, s_port);
    //FIX THE GET ADDR INFO
    
    for(int i = 0; i < db_entries; i++){
        printf("Checking #%d %s\n", i, my_db[i].filename);
        np = &my_db[i];
        if (strcmp(np->filename, file) == 0) { //file found in database
            return;
        }
    }
    // if file not found, add to my_db (i value should be the one pointing to end of table from above
    np = malloc(sizeof(New_peer));
    np->filename = file;
    np->addr = serveraddr;
    np->port = s_port;
    my_db[db_entries] = *np;
    db_entries++;
    // printf("added!\n");
    return;
}

void addFile(char* file, uuid_t uuid)
{
    peer_t p;
    for(int i = 0; i < num_peers; i++)
    {
        if(uuid_compare(uuid, peer_table[i]->uuid) == 0)
        {
            p = peer_table[i];
            printf("Adding file: %s to peer: %s\n", file, p->name);
            p->files[p->num_files] = malloc(sizeof(char)*strlen(file));
            sprintf(p->files[p->num_files], "%s", file);
            peer_table[i]->num_files += 1;
            return;
        }
    }
    printf("No peer with that UUID was found so the file could not be added!\n");
}

//Takes a file name and returns the index of the peer with it in the peer_table
//returns -1 if not found
int fileLook(char* file)
{
    peer_t p;
    printf("num_peers = %d\n", num_peers);
    for(int i = 1; i < num_peers; i++)
    {
        printf("checking peer #%d which has %d files\n", i, p->num_files);
        p = peer_table[i];
        for(int j = 0; j < p->num_files; j++)
        {
            printf("Checking \"%s\"\n", p->files[j]);
            if(strcmp(file, p->files[j]) == 0)
            {
                printf("FOUND\n");
                return i;
            }
        }
    }
    return -1;
}

void sendHeaders(char* file_size, char* filename, int clientfd){
    
    int n;
    char temp[MAXLINE];
    char extension[MAXLINE];
    char* content_type = NULL;
    char response[MAXLINE];
    
    if (sscanf(filename, "%[^.]%s", temp, extension) != 2) {
        printf("500 Internal Server Error:Received a malformed request due to extension \n");
        exit(1);
        return;
    }
    
    ftype *f_ext = file_types;
    while(f_ext->ext){
        if(strcmp(f_ext->ext,extension)==0){
            content_type = f_ext->iana;
            break;
        }
        f_ext++;
    }
    
    if (strcmp(content_type, "x-icon")==0){
        return;
    }
    
    sprintf(response, "HTTP/1.1 200 OK\r\n"
            "Content-Length: %s\r\n"
            "Content-Type: %s\r\n"
            "Connection: Keep-Alive\r\n"
            "Accept-Ranges: bytes\r\n"
            "Date: %s\r\n\r\n", file_size, content_type, get_rfc_time());
    
    // Write response to fd
    
    n = write(clientfd, response, strlen(response));
    printf("The length of the headers: %lu written to clientfd: %d\n\n", strlen(response), clientfd);
    if (n < 0)
        error("ERROR writing to socket");
    // printf("~~~~Sending Headers~~~~~\n%s\n\n", response);

    return;
    
}

int send_len(packet* p)
{
    return (16 + p->length) * sizeof(char);
}


New_flow* flow_look(char flow_ID)
{
    New_flow* nf;
    for(int i = 0; i < flow_entries; i++)
    {
        nf = &my_flow[i];
        if(nf->pack == flow_ID) // Flow exists
        {
            return nf;
        }
    }
    return NULL;
}

int remove_peer(uuid_t uuid)
{
    int res = 0;
    int i;
    peer_t p;
    for(i = 1; i < num_peers; i++)
    {
        p = peer_table[i];
        if(uuid_compare(uuid, p->uuid) == 0) // Flow exists
        {
            res = 1;
            num_peers--;
            break;
        }
    }
    while(i < num_peers)
    {
        peer_table[i] = peer_table[i+1];
        i++;
    }
    return res;
}

int remove_flow(char flow_ID)
{
    int res = 0;
    int i;
    New_flow* nf;
    for(i = 0; i < flow_entries; i++)
    {
        nf = &my_flow[i];
        if(nf->pack == flow_ID) // Flow exists
        {
            res = 1;
            flow_entries--;
            break;
        }
    }
    while(i < flow_entries)
    {
        my_flow[i] = my_flow[i+1];
        i++;
    }
    return res;
}

New_flow flow_add(char flow_ID, struct sockaddr_in addr, uint16_t syn, uint16_t ack, char* path, FILE* file, uint16_t size, int fd, uint16_t window)
{
    New_flow nf;
    nf.pack = flow_ID;
    nf.addr = addr;
    nf.base_syn = syn;
    nf.syn = syn;
    nf.ack = ack;
    strcpy(nf.filename, path);
    nf.file = file;
    nf.file_size = size;
    nf.client_fd = fd;
    nf.window = window;

    my_flow[flow_entries] = nf;
    flow_entries++;
    return nf;
}

void getContent(char* path, int fd)
{
    struct sockaddr_in* provider = NULL;
    unsigned short port;
    char* buf;
    packet* req;
    int index;

    //Look for who has the file in the lookup table
    index = fileLook(path);


    if(index == -1)
    {
        printf("This file has not been added yet\n\n");
        return;
    }

    provider = &(peer_table[index]->addr);
    port = peer_table[index]->back_port;

    //create a new request packet
    req = request_new_packet(path, getFlowID(), back_port, port);
    buf = package(req);
    // printf("Sending Request Packet: \n");
    printPacket(req);

    //Add to Flow Table
    flow_add(req->pack, *provider, req->syn, 0, path, NULL, 0, fd, req->window);

    //send the first request packet out
    //Timeout ask again sitch
    // printf("Send Length: %d\n", send_len(req));
    if(sendto(back_fd, buf, send_len(req), 0, (struct sockaddr*)provider, sizeof(*provider)) < 0)
        printf("Error sending first request packet");
    return;
}


char* package(packet* p) // storing in packet in buf
{
    char* buf = malloc(sizeof(char)*p->length + sizeof(char)*16); 
    memcpy(buf, &(p->flags), 1);
    memcpy(buf+1, &(p->pack), 1);
    memcpy(buf+2, &(p->source_port), 2);
    memcpy(buf+4, &(p->dest_port), 2);
    memcpy(buf+6, &(p->length), 2);
    memcpy(buf+8, &(p->syn), 2);
    memcpy(buf+10, &(p->ack), 2);
    memcpy(buf+12, &(p->window), 2);
    memcpy(buf+14, &(p->rtt), 2);
    memcpy(buf+16, p->data, p->length);
    return buf;
}

packet* unwrap(char* buf)
{
    packet* p = (packet *)malloc(sizeof(packet));
    p->flags = buf[0];
    p->pack = buf[1]; 
    memcpy(&(p->source_port), buf+2, 2);
    memcpy(&(p->dest_port), buf+4, 2);
    memcpy(&(p->length), buf+6, 2);
    memcpy(&(p->syn), buf+8, 2);
    memcpy(&(p->ack), buf+10, 2);
    memcpy(&(p->window), buf+12, 2);
    memcpy(&(p->rtt), buf+14, 2);
    p->data = malloc(sizeof(char) * p->length);
    memcpy(p->data, buf+16, p->length);
    return p;
}


packet* request_new_packet(char* path, char flowID, uint16_t source_port, uint16_t dest_port)
{
    packet* p = (packet*)malloc(sizeof(packet));
    p->flags = 0x04;  //0x0100  Syn, no Ack, no Fin
    p->pack = flowID;
    p->source_port = source_port;
    p->dest_port = dest_port;
    p->length = strlen(path);
    p->syn = 0;
    p->ack = 67;    //NOT IMPORTANT
    p->data = path;
    p->window = window_g;
    return p;
}

static int v;
packet* get_syn_ack(char flowID, uint16_t dest_port, uint16_t ack, char* data)
{

    clock_t t = clock();
    clock_t t1 =  t/CLOCKS_PER_SEC;
    v = t1;
    packet* p = (packet*)malloc(sizeof(packet));

    p->flags = 0x0c;   //0x1100 Syn, Ack, no Fin
    p->pack = flowID;
    p->source_port = back_port;
    p->dest_port = dest_port;
    p->ack = ack + 1;
    p->syn = 0;
    p->length = strlen(data);
    p->data = data;
    p->rtt = t; // base_time for rtt

    return p;
}

static int rtt_val;

packet* get_ack(packet* p, New_flow* nf)
{

    static int rtt;
    // clock_t t = clock();
    p->rtt = p->rtt/CLOCKS_PER_SEC;
    packet* g = (packet*)malloc(sizeof(packet));
    g->rtt = (p->rtt - v);

    rtt_val = g->rtt/1e3; // in seconds

    g->pack = p->pack;
    g->flags = 0x08;
    g->source_port = back_port;
    g->dest_port = p->source_port;
    g->length = 0;
    g->syn = nf->last_ack + 1;
    g->data = NULL;
    if (rtt != 0)
        p->rtt = rtt;
    return g;
    
}




/* Time Declarations */
char* weekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
char* months[] =  {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/*
 * get_rfc_time - returns a string with an RFC 1123 formatted string with the time in GMT
 * input: none
 * output: string - RFC formatted time
 */
char* get_rfc_time() {
    char time_string[30];
    time_t t;
    struct tm* tm;
    time(&t);
    tm = gmtime(&t);
    sprintf(time_string, "%s, %d %s %d %d:%d:%d GMT", weekdays[tm->tm_wday], tm->tm_mday, months[tm->tm_mon],
            (tm->tm_year + 1900), tm->tm_hour, tm->tm_min, tm->tm_sec);
    return (char*)time_string;
}

static int bps = 0;

/*
 * parse - parse function takes care of the parsing of the requet sent by the
 * client. It returns a structure url_info, which contains different parts of
 * request. It returns a PARSE_ERROR if the request was malformed. For example:
 * input : char *buf - pointer to request string.
 * output : url_info parse_url- a structure containing different parsed values.
 *                  .method - "GET"
 *                  .url - "www.example.com:8080/home.html"
 *                  .host - "www.example.com"
 *                  .path - "Users/Sanika/Desktop/cat.jpg"
 *                  .port - "8080"
 *                  .version - 0
 *                  .extension - jpg/txt etc.
 *                  .parse_result - PARSE_CORRECT(PARSE_ERROR if Error)
 */

url_info parse(char *buf){
    char method[MAXLINE];
    char path[MAXLINE];
    char version;
    char temp[MAXLINE];
    char ext[MAXLINE];
    char params[MAXLINE];
    char pm[MAXLINE];
    char* token;
    char key[200];
    char val[200];
    char peer[MAXLINE];
    url_info parse_url;
    
    /* sscanf must parse exactly 3 things for request line to be well-formed */
    /* version must be either HTTP/1.0 or HTTP/1.1 */
    if (sscanf(buf, "%s %s HTTP/1.%c", method, path, &version) != 3
        || (version != '0' && version != '1')) {
        // printf("\n\nBUF: %s\n", buf);
        printf("500 Internal Server Error: Received a malformed request due to method/path/version\n");
        parse_url.result = PARSE_ERROR;
        return parse_url;
    }
    snprintf(parse_url.method , sizeof(method), "%s", method);
    // printf("\n\n\nPATH with everything: %s\n", path);
    if(sscanf(path, "%*c%[^/]%*c%[^?]%s", peer, pm, params) < 2 || strcmp(peer, "peer") !=0)
    {
        printf("\n\nNOT A VALID URI FOR PROJECT 2\n\n");
        parse_url.pm = NONE;
        return parse_url;
    }
    else
    {
        printf("\nPEER: %s\n METHOD: %s\n PARAMS: %s\n", peer, pm, params);
        if(strcmp(pm, "kill") == 0)
        {
            parse_url.pm = KILL;
        }
        else if(strcmp(pm, "uuid") == 0)
        {
            printf("seeing a UUID request\n");
            parse_url.pm = UUID;
        }
        else if(strcmp(pm, "neighbors") == 0)
        {
            printf("seeing a NEIGHBORS request\n");
            parse_url.pm = NEIGHBORS;
        }
        else if(pm[0] == 'v')
        {
            //No parameters means this is a view or status request
            sscanf(pm, "%[^/]/%s", temp, path);
            if(strcmp(temp, "view") == 0)
            {
                token = strtok(NULL, "");
                //VIEW REQUEST
                parse_url.pm = VIEW;
                snprintf(parse_url.path , sizeof(path), "%s", path);
                // printf("PATH: %s\n\n", parse_url.path);
                if (sscanf(path, "%[^.]%s", temp, ext) != 2)
                {
                    printf("500 Internal Server Error:Received a malformed request due to extension \n");
                    parse_url.result = PARSE_ERROR;
                    return parse_url;
                }
                snprintf(parse_url.ext  , sizeof(ext), "%s", ext);
                //printf("\n\nVIEW\npath: %s\next: %s\n", parse_url.path, ext);
            }
        }
        else
        {
            //There are parameters so this an add or config
            if(strcmp(pm, "add") == 0)
            {
                //ADD action
                parse_url.pm = ADD;
            }
            else if(strcmp(pm, "config") == 0)
            {
                //CONFIG action
                parse_url.pm = CONFIG;
            }
            else if(strcmp(pm, "addneighbor") == 0)
            {
                parse_url.pm = ADDNEIGHBOR;
            }
            
            //Parse the parameters
            token = strtok(params, "&");
            token = token + 1;
            while (token)
            {
                sscanf(token, "%[^=]=%s", key, val);
                if(strcmp(key, "path") == 0)
                {
                    snprintf(parse_url.path , sizeof(val), "%s", val);
                    if (sscanf(parse_url.path, "%[^.]%s", temp, ext) != 2)
                    {
                        printf("500 Internal Server Error: File Name incorrectly formatted \n");
                    }
                    snprintf(parse_url.ext , sizeof(ext), "%s", ext);
                }
                if(strcmp(key, "host") == 0)
                {
                    snprintf(parse_url.host , sizeof(val), "%s", val);
                }
                if(strcmp(key, "backend") == 0)
                {
                    parse_url.back_port = (unsigned int)atoi(val);
                }
                if(strcmp(key, "frontend") == 0)
                {
                    parse_url.front_port = (unsigned int)atoi(val);
                }
                if(strcmp(key, "rate") == 0)
                {
                    parse_url.rate = (unsigned int)atoi(val);
                }
                if(strcmp(key, "peer") == 0 || strcmp(key, "uuid") == 0)
                {
                    uuid_parse(val, parse_url.uuid);
                }
                if(strcmp(key, "metric") == 0)
                {
                    parse_url.distance = atoi(val);
                }
                token = strtok(NULL, "&");
            }
        }
        
        
    }

    parse_url.version = version;
    parse_url.result = PARSE_CORRECT;
    return parse_url;
}


static void backend(int on_fd)
{
    char* path;
    char buf[MAXLINE];
    char data[MAXLINE];
    struct sockaddr_in sender;
    long size;
    socklen_t sender_len = sizeof(sender);
    packet* p = malloc(sizeof(packet));
    packet* g = malloc(sizeof(packet));
    New_flow* nf;
    bzero(&sender, sender_len);
    bzero(p, sizeof(packet));
    bzero(g, sizeof(packet));
    bzero(buf, MAXLINE);
    bzero(data, MAXLINE);

    if(recvfrom(on_fd, buf, MAXLINE, 0, &sender, &sender_len) < 0)
    {
        printf("Error receiving packet on Backend Connection\n\n");
        return;
    }
    
    p = unwrap(buf);

    if (rand_close == 1) // connection closed by peer
    {
        remove_flow(p->pack);
        rand_close = 0;
    }

    bzero(buf, MAXLINE);
    // printf("Received Packed of length %lu: \n", (strlen(buf+16)+16));
    printPacket(p);
    if(p->flags == 0x04)
    {
        // printf("Came here\n");
        
        // printf("RECD SYN %d\n", p->syn);
        //No Ack, but Syn

        // printf("Got an Ack but no Syn so let's set up a new connection\n");
        //Receiving a new connection
        if(flow_look(p->pack) != NULL)
        {
            printf("This flow id is already in use!\n\n");
            return;
        }

        //get file length
        path = strcat(peer_table[0]->content_dir, p->data);
        FILE* file = fopen(path, "r");
        if(file == NULL)
        {
            printf("Could not find the desired file\n\n");
            return;
        }
        fseek(file,0, SEEK_END);
        size = ftell(file);
        fseek(file,0, SEEK_SET);

        sprintf(data, "%ld", size);
        // printf("File is of size: %s\n", data);
        
        //Get SYN ACK packet
        g = get_syn_ack(p->pack, p->source_port, (p->syn), data);

        // printf("In packet File is of size: %s\n", g->data);


        //add to Flow Table
        flow_add(p->pack, sender, g->syn, g->ack, p->data, file, size, -1, p->window);
        nf = flow_look(p->pack);
        nf->on_fd = on_fd;
        nf->addr = sender;
        nf->last_ack_time = getTimeMilliseconds();
        nf->last_sent = -1;
        nf->last_ack = -1;
        nf->window_size = 1;
        nf->src_port = p->source_port;
        
        //send syn ack
        memcpy(buf, package(g), send_len(g));
        // printf("Sending Packet of length %lu:\n", (16 + strlen(buf+16)));
        printPacket(g);
        if(sendto(on_fd, buf, send_len(g), 0, (struct sockaddr*)&sender, sender_len) < 0)
        {
            printf("Error while trying to send a SYN ACK");
            return;
        }
        nf->last_sent = 0;
    }
    else if(p->flags == 0x0c)
    {
        //Receiving a SYN ACK
        //find the flow
        // printf("RECD SYN ACK%d\n", p->syn);

        nf = flow_look(p->pack);
        nf->last_ack= -1;

        if(nf == NULL)
        {
            printf("Could not find the flow that a SYN ACK responds to\n");
            return;
        }

        //send headers
        sendHeaders(p->data, nf->filename, nf->client_fd);


        //Check to see that the seq number is good
        if(p->syn != 0)
        {
            printf("Wrong synack packet!! \n");

        }

        //Send ack
        g = get_ack(p, nf);
        

        

        // calculate timeout for this flow
        // nf->time_out = rtt_val + 2;

        // printf("RTT_value: %d", rtt_val);
        // printf("max window size: %u",max_window_size);

        //send ack
        memcpy(buf, package(g), send_len(g));


        //update flow table
        nf->last_ack = g->syn;
        nf->file_size = atoi(p->data);

        // printf("Sending Packet:\n");
        printPacket(g);


        if(sendto(on_fd, buf, send_len(g), 0, (struct sockaddr*)&sender, sizeof(sender)) < 0)
        {
            printf("Error while trying to send a SYN ACK\n");
            return;
        }

    }
    else if(p->flags == 0x08)
    {
        //Normal ACK Case
        // printf("Normal ACK Case\n");
        // printf("\n p->ack: %u, p->syn: %u, nf->base_syn: %u\n\n", p->ack, p->syn, nf->base_syn);
        //Look Up the Flow
        if(rate)
            max_window_size = (rate)*1000*rtt_val;
        else
            max_window_size = 1000;


        // printf("RECD ACK%d\n", p->syn);
        nf = flow_look(p->pack);
        // printf("Blah\n");
        
        if(nf == NULL)
        {
            printf("Could not find the flow that the ACK responds to\n");
            return;
        }
        
        nf->last_ack_time = getTimeMilliseconds(); //update time
        // printf("Last ack updating to %d\n", nf->last_ack_time);
        // printf("Blah2\n");

       if(nf->client_fd == -1)
        {
            //Sender of Data
            // printf("Normal ACK Case -- I am the sender\n");
            //make sure in sync

            // printf("\n p->ack: %u, p->syn: %u, nf->base_syn: %u\n\n", p->ack, p->syn, nf->base_syn);

            // expected nf->syn + 1, got is p->ack
            // printf("LAST ACK is %d\n", nf->last_ack);
            if(p->syn == nf->last_ack + 1){
                // printf("In sync bawse!!!!! :)");
                nf->error = 0; //no error
            } 
            else if (p->syn < nf->last_ack) {
                return;
            } else {
                nf->error = 1;
                // re-tx fucntion ?????????
            }

             // error: p->window = p->window / 2;
            if (nf->error == 1){
                re_tx_last_sender(p,nf,on_fd);
                return;
            }

            nf->last_ack = p->syn;
            // printf("Window size is %d, max is %d\n", nf->window_size, max_window_size);
            if (nf->window_size > max_window_size)
                nf->window_size = max_window_size;
            else
                nf->window_size ++;

            // printf("Window increased to %d\n", nf->window_size);


            // printf("Sending %d new packets\n", nf->window_size - (nf->last_sent - nf->last_ack));
            while(nf->last_sent - nf->last_ack < nf->window_size)
            {
                //Find specified block of data
                /*unsigned long index = p->ack - nf->base_syn - 1;
                fseek(nf->file, 0, SEEK_SET);
                fseek(nf->file, PACKET_SIZE * index, SEEK_SET);*/

                //get ack skeleton
                g = get_ack(p, nf);

                g->pack = p->pack;
                g->flags = 0x08;
                g->source_port = back_port;
                g->dest_port = p->source_port;
                g->length = 0;
                g->syn = nf->last_sent + 1;

                //fill data
                g->data = malloc((sizeof(char))*PACKET_SIZE);
                fseek(nf->file, PACKET_SIZE * nf->last_sent, SEEK_SET);
                unsigned long br = fread(g->data, (sizeof(char)), PACKET_SIZE, nf->file);
                g->length = br;

                //printf("\nRead and forwarded bytes from %lu to %lu\n\n", index*PACKET_SIZE, (index*PACKET_SIZE+br));

                //Check if you finished the file
                if(br < PACKET_SIZE)
                {
                    g->flags = (g->flags | 0x02);  //flags = flags | 0x0010  set FIN flag
                    // printf(" %d lst sent , finished!\n", nf->last_sent);
                }

                //send ack
                memcpy(buf, package(g), send_len(g));
                // printf("Sending Packet:\n");
                printPacket(g);
                // printf("Sending a packet of length %d\n", send_len(g));

                if(sendto(on_fd, buf, send_len(g), 0, (struct sockaddr*)&sender, sizeof(sender)) < 0)
                {
                    // printf("Error while trying to send1 \n");
                    return;
                }
                free(g->data);
                nf->last_sent++;
            }
        }
        else
        {
            //Receiver of Data
            // printf("Normal ACK Case -- I am the receiver with clientfd: %d\n", nf->client_fd);
            // printf("RECD DATA%d\n", p->syn);
            //make sure in sync expected: nf->syn + 1
            if(p->syn <= nf->last_ack)
            {
                printf("Out of sync!!");
                return;
                //resend last packet
            }
            else
                nf->error = 0;

            //Send ack
            //g = get_ack(p, nf); //syn and ack will be updated

            g->pack = p->pack;
            g->flags = 0x08;
            g->source_port = back_port;
            g->dest_port = p->source_port;
            g->length = 0;
            g->syn = nf->last_ack;
            g->data = NULL;

            if (p->syn == nf->last_ack + 1) {
                g->syn = nf->last_ack + 1;
            }

            memcpy(buf, package(g), send_len(g));

            // printf("Sending Packet:\n");
            printPacket(g);


            if (p->syn == nf->last_ack + 1) {
                
                // printf("Writing %u bytes to http server FD %d\n", p->length, nf->client_fd);
                
                if(write(nf->client_fd, p->data, p->length) < 0)
                {
                    printf("Failed writing to client socket with file data\n");
                } else {
                    nf->last_ack ++;
                    if(sendto(on_fd, buf, send_len(g), 0, (struct sockaddr*)&sender, sizeof(sender)) < 0)
                    {
                        // printf("Error while trying to sendd\n");
                        return;
                    }
                }
            }
            
        }

    }
    else if(p->flags == 0x0a)
    {
        //FIN ACK
        // printf("Received a FIN ACK\n");
        //look up flow
        nf = flow_look(p->pack);
        if(nf == NULL)
        {
            // printf("Could not find the flow that the ACK responds to\n");
            return;
        }

        //see if in sync
        if(p->ack - nf->syn != 1)
        {
            // printf("Out of sync!!\n\n");
            nf->window = p->window/2;
            if (nf->window_size == 0) {
                nf->window_size =  1;
            }
            return;
            //resend last packet
        }

        
        if(nf->client_fd != -1)
        {
            //There should be last bit of data to relay
            // printf("Received a FIN ACK -- I am the receiver sending the last bits to HTTP\n");
            //send data
            if(write(nf->client_fd, p->data, p->length) < 0)
            {
                printf("Failed writing to client socket with file data fin wala\n");
            }
            g = get_ack(p, nf);
            g->flags = g->flags | 0x02; //Set the fin flag

            //Send the fin ack
            memcpy(buf, package(g), send_len(g));

            // printf("Sending Packet:\n");
            printPacket(g);

            if(sendto(on_fd, buf, send_len(g), 0, (struct sockaddr*)&sender, sizeof(sender)) < 0)
            {
                // printf("Error while trying to send a SYN ACK\n");
                return;
            }
        }
        // printf("Removing Flow \n\n**********************************************\n");
        remove_flow(nf->pack);
    }
    free(p);
    free(g);
}

void re_tx_last_sender(packet* p, New_flow* nf, int on_fd){

    packet* g = malloc(sizeof(packet));
    char buf[MAXLINE];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    
    //Find specified block of data
    /*unsigned long index = p->ack - nf->base_syn - 1;
    fseek(nf->file, 0, SEEK_SET);
    fseek(nf->file, PACKET_SIZE * index, SEEK_SET);*/

    //get ack skeleton
    g = get_ack(p, nf);

    //fill data
    g->data = malloc((sizeof(char))*PACKET_SIZE);
    fseek(nf->file, PACKET_SIZE * (nf->last_ack), SEEK_SET);
    unsigned long br = fread(g->data, (sizeof(char)), PACKET_SIZE, nf->file);
    g->length = br;

    //printf("\nRead and forwarded bytes from %lu to %lu\n\n", index*PACKET_SIZE, (index*PACKET_SIZE+br));

    //Check if you finished the file
    if(br < PACKET_SIZE)
    {
        g->flags = (g->flags | 0x02);  //flags = flags | 0x0010  set FIN flag
        // printf("finished!\n");
    }

    //send ack
    memcpy(buf, package(g), send_len(g));
    // printf("Sending Packet:\n");
    printPacket(g);
    // printf("Sending a packet of length %d\n", send_len(g));

    if(sendto(on_fd, buf, send_len(g), 0, (struct sockaddr*)&nf->addr, sizeof(sender)) < 0)
    {
        // printf("Error while trying to send 2\n");
        return;
    }
}



void config(char* conf_file)
{
    int peer_count = 1; //1 because 0th peer is always self
    peer_t self = malloc(sizeof(peer));
    FILE* file;
    char* line;
    char key[MAXLINE];
    char val[MAXLINE];
    size_t len = 0;

    //set defaults
    self->content_dir = NULL;
    self->distance = 0;
    bzero(self->uuid, 16);

    file = fopen(conf_file, "r");
    if(file == NULL)
    {
        printf("Config File: %s could not be found!\n", conf_file);
        exit(1);
    }
    while (getline(&line, &len, file) != -1) {
        //printf("line: %s", line);
        sscanf(line, "%[^ ] = %[^\n]", key, val);
        //printf("key: \"%s\"\nval: \"%s\"\n\n", key, val);
        if(strcmp(key, "uuid") == 0)
        {
            if(uuid_parse(val, self->uuid) == -1)
            {
                printf("Problem parsing uuid string given\n");
            }
        }
        if(strcmp(key, "name") == 0)
        {
            sprintf(self->name, "%s", val);
        }
        if(strcmp(key, "frontend_port") == 0)
        {
            self->front_port = (unsigned int)atoi(val);
        }
        if(strcmp(key, "backend_port") == 0)
        {
            self->back_port = (unsigned int)atoi(val);
        }
        if(strcmp(key, "content_dir") == 0)
        {
            self->content_dir = malloc(sizeof(char)*strlen(val));
            sprintf(self->content_dir, "%s", val);
        }
        if(strcmp(key, "peer_count") != 0 && strstr(key, "peer_") != NULL)
        {
            peer_t np = malloc(sizeof(peer));
            char uuid_str[MAXLINE];
            char host[MAXLINE];
            sscanf(val, "%[^,],%[^,],%hu,%hu,%d", uuid_str, host, &(np->front_port), &(np->back_port), &(np->distance));
            if(uuid_parse(uuid_str, np->uuid) == -1)
            {
                printf("Problem parsing peer's uuid string given\n");
            }
            np->name = malloc(sizeof(char)*strlen(key));
            sprintf(np->name, "%s", key);

            np->host = malloc(sizeof(char)*strlen(host));
            sprintf(np->host, "%s", host);

            np->content_dir = malloc(sizeof(char)*9);
            np->content_dir = "content/";
            np->num_files = 0;
            np->last_sent = getTimeMilliseconds();
            np->last_received = getTimeMilliseconds();
            np->addr = get_sockaddr_from_host(np->host, np->back_port);
            //printPeer(np);
            peer_table[peer_count] = np;
            peer_count++;
        }
    }
    if(uuid_is_null(self->uuid))
    {
        //Generate UUID
        printf("Need to generate UUID\n");
        uuid_generate(self->uuid);
        //Save to config file
        fclose(file);
        file = fopen(conf_file, "a");

        if(file == NULL)
        {
            printf("Config File: %s could not be found!\n", conf_file);
        }

        bzero(key, MAXLINE);
        bzero(val, MAXLINE);
        uuid_unparse(self->uuid, val);
        sprintf(key, "\nuuid = %s", val);
        fwrite(key, strlen(key), 1, file);
        fclose(file);
    }
    if(self->content_dir == NULL)
    {
        printf("default content dir\n");
        //default content dir
        self->content_dir = malloc(sizeof(char)*9);
        self->content_dir = "content/";
    }
    if(self->front_port == 0 || self->back_port == 0)
    {
        printf("Ports not specified!\n");
    }
    //printPeer(self);
    self->num_files = 0;
    self->last_sent = getTimeMilliseconds();
    self->last_received = getTimeMilliseconds();
    peer_table[0] = self;
    num_peers = peer_count;
    return;

}


int main(int argc, char **argv) {
    int listenfd; /* listening socket for http */
    int portno; /* port to listen on */
    int on_fd;
    int result;
    int new_fd = 0;
    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in backaddr;
    int optval; /* flag value for setsockopt */
    fd_set curr_set, live_set; /* Set of active fd's */ 
    char* conf = "node.conf";
    
    signal(SIGPIPE,SIG_IGN); //Sigpipe handling
    
    /* check command line args */
    if (argc > 3) {
        fprintf(stderr, "usage: %s -c <config_file>\n", argv[0]);
        exit(1);
    }
    if (argc == 3)
    {
        if (strcmp(argv[1], "-c") == 0)
            conf = argv[2];
        else
        {
            fprintf(stderr, "usage: %s -c <config_file>\n", argv[0]);
            exit(1);
        }

    }
    
    config(conf);

    portno = peer_table[0]->front_port;
    back_port = peer_table[0]->back_port;

    srand(time(NULL)); //Initialize random number generator

    /* socket: create a socket */
    listenfd = socket(AF_INET, SOCK_STREAM, 0);
    back_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (listenfd < 0)
        error("ERROR opening socket");
    if (back_fd < 0)
        error("ERROR opening backend socket");
    
    /* setsockopt: Handy debugging trick that lets
     * us rerun the server immediately after we kill it;
     * otherwise we have to wait about 20 secs.
     * Eliminates "ERROR on binding: Address already in use" error.
     */
    optval = 1;
    setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval , sizeof(int));
    
    /* build the server's internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET; /* we are using the Internet */
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY); /* accept reqs to any IP addr */
    serveraddr.sin_port = htons((unsigned short)portno); /* port to listen on */
    
    setsockopt(back_fd, SOL_SOCKET, SO_REUSEADDR,
               (const void *)&optval , sizeof(int));
    
    /* build the server's internet address */
    bzero((char *) &backaddr, sizeof(backaddr));
    backaddr.sin_family = AF_INET; /* we are using the Internet */
    backaddr.sin_addr.s_addr = htonl(INADDR_ANY); /* accept reqs to any IP addr */
    backaddr.sin_port = htons((unsigned short)back_port); /* port to listen on */
    
    /* bind: associate the listening socket with a port */
    if (bind(listenfd, (struct sockaddr *) &serveraddr,
             sizeof(serveraddr)) < 0)
        error("ERROR on binding");
    
    if (bind(back_fd, (struct sockaddr *) &backaddr,
             sizeof(backaddr)) < 0)
        error("ERROR on binding backend");
    
    /* listen: make it a listening socket ready to accept connection requests */
    if (listen(listenfd, 5) < 0) /* allow 5 requests to queue up */
        error("ERROR on listen");

    fcntl(listenfd, F_SETFL, O_NONBLOCK);
    FD_ZERO(&curr_set);
    FD_ZERO(&live_set);
    FD_SET(listenfd, &live_set);
    FD_SET(back_fd, &live_set);//add live_set to listening and backend fd??
    
    /* main loop */
    // int akskd = 0;
    uint64_t last_timeout_check = getTimeMilliseconds();
    while (1) {
        // printf("%d\n", akskd++);
        //printf("hiiii!~ER@#$T~~~~~~~~~~~~\n");
        curr_set = live_set;
        // curr_set always overwritten from the beginning???\
        // where do we set FD_SETSIZE?
        struct timeval tv = {0, 100000};

        result = select(FD_SETSIZE, &curr_set, NULL, NULL, &tv);

        // printf("Selected \n");

        // printf("FD list ");
        for (on_fd = 0; on_fd < FD_SETSIZE; ++on_fd) {
            if (FD_ISSET(on_fd, &curr_set)) {
                printf("%d ", on_fd);
            }
        }
        // printf("\n");
        for(on_fd = 0; on_fd < FD_SETSIZE; ++on_fd)
        {
            if (FD_ISSET(on_fd, &curr_set))
            {
         //printf("ON_FD is %d \n", on_fd);
                if(on_fd == listenfd)
                {

                    // printf("new TCP conn\n");
                    // printf("ON_FD is %d \n", on_fd);
                    //Listening Port Got a Request
                    
                    
                        new_fd = accept(listenfd, NULL, NULL);
                        if(new_fd < 0)
                        {
                            printf("ACCEPT Failed with error fd: %d\n", new_fd);
                        }
                        else{
                            printf("  New incoming connection - %d\n", new_fd);
                            FD_SET(new_fd, &live_set);
                            fcntl(new_fd, F_SETFL, O_NONBLOCK);
                            
                        }
                        
                        if (listen(listenfd, 5) < 0) /* allow 5 requests to queue up */
                            error("ERROR on listen");
                        FD_SET(listenfd, &live_set);
                }
                else if(on_fd == back_fd)
                {
                    //printf("backend\n");
                    //BACKEND PORT WANTS SOME SERVICE
                    //recvfrom/
                    // printf("Starting backend routine\n");
                    backend(on_fd);
                    // printf("Ending backend routine\n");
                }
                else
                {
                    // printf("ON_FD is %d \n", on_fd);
                    // printf("serve this biatch\n");
                    //SERVICE -- Get Request -- Could be ADD, VIEW, CONFIG, OR OTHER
                    // printf("  Descriptor %d is readable\n", on_fd);
                    serve(on_fd, &live_set);
                    // printf("Ending server routine\n");
                }
            }
        }

        if (getTimeMilliseconds() - last_timeout_check > 100) {
            uint64_t current = getTimeMilliseconds();
            // printf("Flow entries is %d\n", flow_entries);
            for(int i = 0; i < flow_entries; i++)
            {
                
                New_flow *nf = &my_flow[i];
                if (nf->client_fd != -1) {
                    break;
                }
                // printf("Trying flow %d\n", i);
                char buf[MAXLINE];
                struct sockaddr_in sender;
                socklen_t sender_len = sizeof(sender);
                packet* p = malloc(sizeof(packet));
                packet* g = malloc(sizeof(packet));
                bzero(&sender, sender_len);

                if (current - nf->last_ack_time > 500) {
                    // printf("TImeout: diff is %d\n", current - nf->last_ack_time);
                    nf->last_ack_time = current;
                    nf->window_size = nf->window_size / 2;
                    if (nf->window_size == 0) {
                        nf->window_size =  1;
                    }
                    nf->last_sent = nf->last_ack;
                    while(nf->last_sent - nf->last_ack < nf->window_size)
                    {
                        //Find specified block of data
                        /*unsigned long index = p->ack - nf->base_syn - 1;
                        fseek(nf->file, 0, SEEK_SET);
                        fseek(nf->file, PACKET_SIZE * index, SEEK_SET);*/

                        //get ack skeleton

                        g->pack = nf->pack;
                        g->flags = 0x08;
                        g->source_port = back_port;
                        g->dest_port = nf->src_port;
                        g->length = 0;
                        g->syn = nf->last_sent + 1;

                        //fill data
                        g->data = malloc((sizeof(char))*PACKET_SIZE);
                        fseek(nf->file, PACKET_SIZE * nf->last_sent, SEEK_SET);
                        unsigned long br = fread(g->data, (sizeof(char)), PACKET_SIZE, nf->file);
                        g->length = br;

                        //printf("\nRead and forwarded bytes from %lu to %lu\n\n", index*PACKET_SIZE, (index*PACKET_SIZE+br));

                        //send ack
                        memcpy(buf, package(g), send_len(g));
                        // printf("Sending Packet:\n");
                        printPacket(g);
                        // printf("Sending a packet of length %d\n", send_len(g));

                        if(sendto(nf->on_fd, buf, send_len(g), 0, (struct sockaddr*)&nf->addr, sizeof(sender)) < 0)
                        {
                            printf("Error while trying to send 3\n");
                        }
                        free(g->data);
                        nf->last_sent++;
                    }
                }
                free(p);
                free(g);
            }
            last_timeout_check = getTimeMilliseconds();
        }
    }
}

struct sockaddr_in get_sockaddr_from_host(char* host, uint16_t back_port)
{
    struct sockaddr_in serveraddr;
    struct hostent *server;
    int sockfd;

    /* socket: create the socket */

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname((const char *)host); 
    
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", host);
        exit(1);
    }

    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(back_port);
    return serveraddr;
}

void* serve(int connfd, fd_set* live_set)
{
    char buf[BUFSIZE]; /* message buffer */
    int n; /* message byte size */
    char *token = NULL;
    char key[200];
    char val[200];
    char json[60];
    char uuid_str[40];
    int range_low = -1;
    int range_high = -1;
    char* content_type = ""; 
    
    /* read: read input string from the client */
    bzero(buf, BUFSIZE);
    
    n = read(connfd, buf, BUFSIZE);
    if (n < 0){
        error("ERROR reading from socket");
        rand_close=1;
    }

    //Parse the request
    url_info* sample = (url_info*)malloc(sizeof(url_info));
    bzero(sample, sizeof(url_info));
    *sample = parse(buf);

    if(sample->result == 0)
    {
        FD_CLR(connfd, live_set);
        close(connfd);
        return NULL;
    }
    // 
    // printf("%s parsed in to method: %s\npath: %s\n host: %s\n backend_port: %u\n rate: %u\nextension: %s\n",
           // buf, sample->method, sample->path, sample->host, sample->back_port, sample->rate, sample->ext);   
    

    if (sample->rate != 0)
        rate = sample->rate;


    //Parse the headers
    token = strtok(buf, "\r\n");
    token = strtok(NULL, "\r\n");
    while (token) {

        sscanf(token, "%[^:]: %s", key, val);
        if(strcmp(key, "Range") == 0)
        {
            sscanf(val, "%*[^=]=%d-%d", &range_low, &range_high);
        }
        if(strcmp(key, "Connection") == 0 && strcmp(val, "close") == 0)
        {
            FD_CLR(connfd, live_set);
            close(connfd);
        }
        token = strtok(NULL, "\r\n");
    }

    ftype *f_ext = file_types;
    while(f_ext->ext){
        if(strcmp(f_ext->ext,sample->ext)==0)
        {
            content_type = f_ext->iana;
            break;
        }
        f_ext++;
    }

    if (strcmp(content_type, "x-icon")==0)
    {
        return NULL;
    }
    printf("peer method: %d\n", sample->pm);
    bzero(buf, BUFSIZE);
    
    switch(sample->pm)
    {
        case 1:   //ADD
            
            printf("HTTP Server has seen a peer ADD request\n");

            printf("Adding file: \"%s\" to peer: %s\n", sample->path, (char*)sample->uuid);
            addFile(sample->path, sample->uuid);
            break;

        case 0:   //VIEW
            printf("HTTP Server has seen a peer VIEW request\n");
            printf("Looking for \"%s\"\n", sample->path);
            getContent(sample->path, connfd);
            break;

        case 2:   //CONFIG
            printf("HTTP Server has seen a peer CONFIG request\n");
            bps = sample->rate;
            break;
        case 5:  //KILL
            printf("HTTP Server has seen a peer KILL request\n");
            exit(0);
            break;
        case 6:  //UUID
            printf("HTTP Server has seen a peer UUID request\n");
            uuid_unparse(peer_table[0]->uuid, uuid_str);
            sprintf(json, "{\"uuid\":\"%s\"}", uuid_str);
            sprintf(buf, "HTTP/1.%c 200 OK\r\n"
            "Content-Length: %lu\r\n"
            "Content-Type: application/json\r\n"
            "Date: %s\r\n"
            "Connection: Keep-Alive\r\n\r\n", sample->version, strlen(json), get_rfc_time());
            n = write(connfd, buf, strlen(buf));
            n = write(connfd, json, strlen(json));
            break;
        case 7:  //ADDNEIGHBOR
            printf("HTTP Server has seen a peer ADDNEIGHBOR request\n");
            addNeighbor(sample->uuid, sample->host, sample->back_port, sample->front_port, sample->distance);
            printPeer(peer_table[num_peers-1]);
            break;
        case 8:
            printf("HTTP Server has seen a peer NEIGHBORS request\n");
            token = tableToJSON();
            sprintf(buf, "HTTP/1.%c 200 OK\r\n"
            "Content-Length: %lu\r\n"
            "Content-Type: application/json\r\n"
            "Date: %s\r\n"
            "Connection: Keep-Alive\r\n\r\n", sample->version, strlen(token), get_rfc_time());
            n = write(connfd, buf, strlen(buf));
            n = write(connfd, token, strlen(token));
            break;

        default:  //
            printf("HTTP Server has seen an unsupported request\n");
            break;
    }

    
    return NULL;
}
