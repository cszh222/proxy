/*
 * proxy.c - CS:APP Web proxy
 *
 * TEAM MEMBERS: (put your names here)
 *     Student Name1, student1@cs.uky.edu 
 *     Student Name2, student2@cs.uky.edu 
 * 
 * IMPORTANT: Give a high level description of your code here. You
 * must also provide a header comment at the beginning of each
 * function that describes what that function does.
 */ 

#include "csapp.h"
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct{
    char *hostname;
    struct hostent *hostentry;
    struct DNScache *next;
} DNScache;

typedef struct {
    char *full_uri;
    char *filename;
    struct pageCache *next;
}pageCache;

pageCache *pageCacheStart;
DNScache *DNSListStart;

/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path, int  *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);
void handle_request(int client_sock, struct sockaddr *address);
int get_uri(char *request_buff, char *method_buff, char *uri_buff, char *version_buff);
void create_error_response(char* response_buff, int status, char* status_message);
DNScache* find_cache_in_list(char* host_name);
DNScache* add_cache_to_list(char* host_name);
int my_open_clientfd(struct hostent *cached_host_entry, int port);
pageCache* find_page_cache(char *uri);
pageCache* create_page_cache(char *uri);
int open_existing_page_cache(pageCache *cache_entry);
int open_new_page_cache(pageCache *cache_entry, char *hostname);
void write_to_client(int cache_fd, int client_sock);
void write_to_cache_and_client(int server_sock,int client_sock, int cache_fd);
int CLRF_detector(char cur_char, int cur_state);
int HTML_close(char cur_char, int cur_state);
/*void read_request_line(char* request_buff, int client_sock);*/
/* 
 * main - Main routine for the proxy program 
 */
int main(int argc, char **argv)
{   
    DNSListStart = NULL;
    pageCacheStart = NULL;
    int port = 0;
    /* Check arguments */
    if (argc != 2) {
	port = 15213;
	fprintf(stderr, "Using port: %d\r\n", port);
    }
    else{
	port = atoi(argv[1]);
	fprintf(stderr, "Using port: %d\r\n", port);
    }

    /* open listening socket */
    int proxy_sock = Open_listenfd(port);

    /* socket struct */
    struct sockaddr addr;
    socklen_t socklen = sizeof(addr); 

    /*seed for random number needed later*/
    srand(time(NULL));

    int status;
    time_t start;
    time_t stop;
    start = time(NULL);
    /*loop infinitely waiting on client*/
    while(1)
    {
       /* Wait for a connection. */
       int client_sock = Accept(proxy_sock, &addr, &socklen);

       if(client_sock>0)       
          handle_request(client_sock, &addr);/*handle request from the client*/
       

       stop = time(NULL);
       if(difftime(stop, start) >= 10.0){
            wait(&status);
            start = time(NULL);
       }
    }

    exit(0);
}

void handle_request(int client_sock, struct sockaddr *address){
    /*port number of request uri*/
    int port;
    int server_sock;
    
    char method_buff[MAXLINE];
    bzero(method_buff, MAXLINE);
    char request_buff[MAXLINE];
    bzero(request_buff, MAXLINE);
    char uri_buff[MAXLINE];
    bzero(uri_buff, MAXLINE);
    char version_buff[MAXLINE];
    bzero(version_buff, MAXLINE);
    char host_buff[MAXLINE];
    bzero(host_buff, MAXLINE);
    char path_buff[MAXLINE];
    bzero(path_buff, MAXLINE);
    char response_buff[MAXLINE];
    bzero(response_buff, MAXLINE);

    bool dns_cached = false;
    bool page_cached = false;

    /* initialize rio for client*/
    rio_t rio_client;
    Rio_readinitb(&rio_client, client_sock);

    /*read the first line of the request*/
    Rio_readlineb(&rio_client,request_buff,MAXLINE);
    /*read_request_line(request_buff, client_sock);*/
    fprintf(stderr, "Request: %s\n", request_buff);
    /*get the uri from request*/
    if(get_uri(request_buff, method_buff, uri_buff, version_buff) == -1){
        /* Bad request, send back error message*/
        create_error_response(response_buff, 400, "Bad Request");
        Rio_writen(client_sock, response_buff, strlen(response_buff));
        close(client_sock);
        return;      
    }

    /*only allow get methods*/
    if(strcmp(method_buff, "GET")!=0){
        create_error_response(response_buff, 400, "Bad Request");
        Rio_writen(client_sock, response_buff, strlen(response_buff));
        close(client_sock);
        return;
    }

    /*parse the uri*/
    if(parse_uri(uri_buff, host_buff, path_buff, &port) == -1){
        /* Invalid uri, send back error message*/
        create_error_response(response_buff, 400, "Bad Request");
        Rio_writen(client_sock, response_buff, strlen(response_buff));
        close(client_sock); 
        return;      
    }
        
    /*have separated uri into host, path and port*/
    /*see if host is in cache*/
    DNScache *host_cache = find_cache_in_list(host_buff);
    if(host_cache == NULL)
        host_cache = add_cache_to_list(host_buff);
    else{
        dns_cached = true;
        fprintf(stderr,"********************DNS LOADED FROM CACHE*************************\n");
    }

    pageCache *page_cache = find_page_cache(uri_buff);
    if(page_cache == NULL){
        page_cache = create_page_cache(uri_buff);
    }
    else{
        page_cached = true;
        fprintf(stderr,"********************PAGE CAN BE LOADED FROM CACHE********************\n");
    }    

    /*fork off a child to process server and client connection*/
    if(fork()!=0){
        close(client_sock);
        return;
    }

    /*write to client from cache*/
    if(page_cached){
        fprintf(stderr, "********************WRITING FROM PAGE CACHE********************\n");
        int cache_fd;        
        cache_fd = open_existing_page_cache(page_cache);
        write_to_client(cache_fd, client_sock);

        close(cache_fd);
        close(client_sock);
        exit(0);
    }

    /*connect to requested server using the official host, only if page is not cached*/  
    if((server_sock = Open_clientfd(host_cache->hostentry->h_name, port)) < 0){
        create_error_response(response_buff, 404, "Not Found");
        Rio_writen(client_sock, response_buff, strlen(response_buff));
        fprintf(stderr, "%s", response_buff);
        close(client_sock);
        exit(0);     
    }

    fprintf(stderr, "Connect to:\n hostname: %s\n\n", host_cache->hostentry->h_name);
    pid_t pid;
    int status;
    if((pid = fork())==0){
        int cache_fd;
        fprintf(stderr, "********************WRITING FROM SERVER**************************\n");
        cache_fd = open_new_page_cache(page_cache, host_cache->hostentry->h_name);
        write_to_cache_and_client(server_sock, client_sock, cache_fd);       
        
        close(cache_fd);
        close(client_sock);
        close(server_sock);
        exit(0);
    }

    /*send request to server*/
    sprintf(request_buff, "%s /%s %s", method_buff, path_buff, version_buff);    
    Rio_writen(server_sock, request_buff, strlen(request_buff)); 
    fprintf(stderr, "client: %s", request_buff);

    char c;
    int CLRF_state = 0;
    while(Rio_readnb(&rio_client, &c, 1)>0 && CLRF_state != 4){
        /*read from client and write to server*/
        if(rio_writen(server_sock, &c, 1)==-1)
            break;
        fprintf(stderr, "%c", c);
        /*check for CRLF CRLF*/
        CLRF_state = CLRF_detector(c, CLRF_state);
    }
    /*write last line of request*/
    /*Rio_writen(server_sock, request_buff, strlen(request_buff));
    fprintf(stderr, "client: %s", request_buff); */
    fprintf(stderr, "********************WAITING ON CHILD******************************\n");
    waitpid(pid, &status, 0);
    fprintf(stderr, "********************FINISHED CONNECTION***************************\n");   
    close(client_sock);
    close(server_sock);
    exit(0);
}

int open_existing_page_cache(pageCache *cache_entry){
    int fd;
    fd = Open(cache_entry->filename, O_RDONLY, S_IRUSR);

    return fd;
}

int open_new_page_cache(pageCache *cache_entry, char *hostname){
    int fd;
    char file_path[MAXLINE];
    char random[MAXLINE];
    sprintf(random, "%d", rand());
    strcpy(file_path, "cache/");
    strncat(file_path, hostname, strlen(hostname));
    strncat(file_path, random, strlen(random));
    cache_entry->filename = strdup(file_path);
    fd = Open(file_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);

    return fd;
}

pageCache* find_page_cache(char *uri){
    if(pageCacheStart == NULL)
        return NULL;
    pageCache *cur_cache = pageCacheStart;
    pageCache *found_cache = NULL;

    do {
        if(strcmp(cur_cache->full_uri, uri) == 0)
            found_cache = cur_cache;
    }while((cur_cache = (pageCache*)cur_cache->next) != NULL);
    return found_cache;
}

pageCache* create_page_cache(char *uri){
    pageCache *new_cache = (pageCache*)malloc(sizeof(pageCache));
    new_cache->full_uri = strdup(uri);

    new_cache->filename = NULL;
    new_cache->next = NULL;

    if(pageCacheStart == NULL){
        pageCacheStart = new_cache;
        return new_cache;
    }
    /*iterate to back of list*/
    pageCache *cur_cache = pageCacheStart;
    while(cur_cache->next != NULL)
       cur_cache = (pageCache*)cur_cache->next;
    cur_cache->next = (struct pageCache*)new_cache;

    return new_cache;
}

void write_to_cache_and_client(int server_sock,int client_sock, int cache_fd){ 
    /*intialize rio buffer for reading*/
    rio_t rio_read;
    Rio_readinitb(&rio_read, server_sock);
    char c;
    while(Rio_readnb(&rio_read, &c, 1)>0){
        if(rio_writen(client_sock, &c, 1)==-1)
            break;
        if(rio_writen(cache_fd, &c, 1) == -1)
            break;
    }
    
    fprintf(stderr, "****************SENT ALL STUFFS******************");
}

void write_to_client(int cache_fd, int client_sock){
    fprintf(stderr, "IN WRITE TO CLIENT\n");
    char c;
    while(Read(cache_fd, &c, 1) > 0 ){
        if(rio_writen(client_sock, &c, 1)==-1)
            break;
    } 
} 

int CLRF_detector(char cur_char, int cur_state){
    /*check for CRLF CRLF*/
        switch (cur_char){
            case '\r':
                switch(cur_state){
                    case 0: return ++cur_state;
                    case 2: return ++cur_state;
                    default: return 0;
                }
                break;
            case '\n':
                switch(cur_state){
                    case 1: return ++cur_state;
                    case 3: return ++cur_state;
                    default: return 0;
                }
                break;
            default: return 0;
        }
}


int get_uri(char *request_buff,char *method_buff, char *uri_buff, char *version_buff){
    /*request is null*/
    if(request_buff == NULL)
        return -1;
    /*tokenize the request line on whitespace*/
    char *method = strtok(request_buff, " ");
    char *uri = strtok(NULL, " ");
    char *version = strtok(NULL, " ");

    /*check none of the above is null*/
    if(method == NULL || uri == NULL || version == NULL){
        return -1;
    }
    strncpy(method_buff, method, strlen(method));
    /*copy uri and version to buffer*/
    strncpy(uri_buff,uri,strlen(uri));
    /*this is added because strpbrk does not search terminating null-character*/
    /*needed for parse_uri to parse correctly*/
    if(uri_buff[strlen(uri)-1] != '/'){
        uri_buff[strlen(uri)] = '/';
        uri_buff[strlen(uri)+1] = '\0';
    }
    strncpy(version_buff,version,strlen(version));

    return 0;
}

void create_error_response(char* response_buff, int status, char* status_message){
    char response_body[MAXLINE];
    char response_header[MAXLINE];
    
    //create error response body
    sprintf(response_body,
        "<html><head><title>%s</title></head><body>%d %s</body></html>",
        status_message, status, status_message);

    //create error response header
    sprintf(response_header,
        "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d",
        status, status_message, strlen(response_body));

    sprintf(response_buff, "%s\r\n\r\n%s", response_header, response_body);

    return;
}

DNScache* find_cache_in_list(char* host_name){
    if(DNSListStart == NULL)
        return NULL;
    DNScache *cur_cache = DNSListStart;
    DNScache *found_cache = NULL;

    do {
        if(strcmp(cur_cache->hostname, host_name) == 0)
            found_cache = cur_cache;
    }while((cur_cache = (DNScache*)cur_cache->next) != NULL);
    return found_cache;
}

DNScache* add_cache_to_list(char* host_name){
    DNScache *new_cache = (DNScache*)malloc(sizeof(DNScache));
    new_cache->hostname = strdup(host_name);

    struct hostent *new_hostent = Gethostbyname(host_name);
    fprintf(stderr, "HERE");
    new_cache->hostentry = new_hostent;
    new_cache->next = NULL;

    if(DNSListStart == NULL){
        DNSListStart = new_cache;
        return new_cache;
    }
    /*iterate to back of list*/
    DNScache *cur_cache = DNSListStart;
    while(cur_cache->next != NULL)
       cur_cache = (DNScache*)cur_cache->next;
    cur_cache->next = (struct DNScache*)new_cache;

    return new_cache;
}

int my_open_clientfd(struct hostent *cached_host_entry, int port){
    /*this is copied from open_clientfd in csapp.c
    but replaced gethostbyname with the cached host entry*/
    int clientfd;
    struct hostent *hp;
    struct sockaddr_in serveraddr;

    if ((clientfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    return -1; /* check errno for cause of error */

    /* Fill in the server's IP address and port */
    if ((hp=cached_host_entry) == NULL)
    return -2; /* check h_errno for cause of error */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)hp->h_addr_list[0], 
      (char *)&serveraddr.sin_addr.s_addr, hp->h_length);
    serveraddr.sin_port = htons(port);

    /* Establish a connection with the server */
    if (connect(clientfd, (SA *) &serveraddr, sizeof(serveraddr)) < 0)
    return -1;
    return clientfd;
}

void read_request_line(char* request_buff, int client_sock){
    char c;
    char* it = request_buff;
    Rio_readn(client_sock, &c, 1);
    while(c != '\n'){
        *it = c;
        it++;
        Rio_readn(client_sock, &c, 1);
    }
    *it = '\n';
}
/* 

/*
 * parse_uri - URI parser
 * 
 * Given a URI from an HTTP proxy GET request (i.e., a URL), extract
 * the host name, path name, and port.  The memory for hostname and
 * pathname must already be allocated and should be at least MAXLINE
 * bytes. Return -1 if there are any problems.
 */
int parse_uri(char *uri, char *hostname, char *pathname, int *port)
{
    char *hostbegin;
    char *hostend;
    char *pathbegin;
    int len;

    if (strncasecmp(uri, "http://", 7) != 0) {
	hostname[0] = '\0';
	return -1;
    }
       
    /* Extract the host name */
    hostbegin = uri + 7;
    hostend = strpbrk(hostbegin, " :/\r\r\n\0");
    len = hostend - hostbegin;
    strncpy(hostname, hostbegin, len);
    hostname[len] = '\0';

    /* Extract the port number */
    *port = 80; /* default */
    if (*hostend == ':')   
	   *port = atoi(hostend + 1);
    /* Extract the path */
    pathbegin = strchr(hostbegin, '/');
    if (pathbegin == NULL) {
	pathname[0] = '\0';
    }
    else {
	pathbegin++;	
	strcpy(pathname, pathbegin);
    }
    return 0;
}

/*
 * format_log_entry - Create a formatted log entry in logstring. 
 * 
 * The inputs are the socket address of the requesting client
 * (sockaddr), the URI from the request (uri), and the size in bytes
 * of the response from the server (size).
 */
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, 
		      char *uri, int size)
{
    time_t now;
    char time_str[MAXLINE];
    unsigned long host;
    unsigned char a, b, c, d;

    /* Get a formatted time string */
    now = time(NULL);
    strftime(time_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    /* 
     * Convert the IP address in network byte order to dotted decimal
     * form. Note that we could have used inet_ntoa, but chose not to
     * because inet_ntoa is a Class 3 thread unsafe function that
     * returns a pointer to a static variable (Ch 13, CS:APP).
     */
    host = ntohl(sockaddr->sin_addr.s_addr);
    a = host >> 24;
    b = (host >> 16) & 0xff;
    c = (host >> 8) & 0xff;
    d = host & 0xff;


    /* Return the formatted log entry string */
    sprintf(logstring, "%s: %d.%d.%d.%d %s", time_str, a, b, c, d, uri);
}


