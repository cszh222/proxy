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

typedef struct{
    char *hostname;
    struct hostent *hostentry;
    struct DNScache *next;
} DNScache;

DNScache *DNSListStart;
/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path, int  *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);
void handle_request(int client_sock, struct sockaddr *address);
int get_uri(char *request_buff, char *uri_buff, char *version_buff);
void create_error_response(char* response_buff, int status, char* status_message);
DNScache* find_cache_in_list(char* host_name);
DNScache* add_cache_to_list(char* host_name);
int my_open_clientfd(struct hostent *cached_host_entry, int port);
/* 
 * main - Main routine for the proxy program 
 */
int main(int argc, char **argv)
{   
    DNSListStart = NULL;

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

    /* Loop infinitely waiting on client */
    while(1)
    {
       /* Wait for a connection. */
       int client_sock = Accept(proxy_sock, &addr, &socklen);

       /*handle request from the client*/
       handle_request(client_sock, &addr);
       waitpid(-1, NULL, WNOHANG);
       /* wait for any child process to exit and reap it*/
    }

    exit(0);
}

void handle_request(int client_sock, struct sockaddr *address){
    /*port number of request uri*/
    int port;
    int server_sock;
    
    char request_buff[MAXLINE];
    char uri_buff[MAXLINE];
    char version_buff[MAXLINE];
    char host_buff[MAXLINE];
    char path_buff[MAXLINE];
    char response_buff[MAXLINE];

    /* initialize rio for client*/
    rio_t rio_client;
    Rio_readinitb(&rio_client, client_sock);

    /*read the first line of the request*/
    Rio_readlineb(&rio_client,request_buff,MAXLINE);
    /*get the uri from request*/
    if(get_uri(request_buff, uri_buff, version_buff) == -1){
        /* Bad request, send back error message*/
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
    /*loaded the DNS cache with hostent struct*/

    /*fork off a child to process server and client connection*/
    pid_t pid;
    int status;
    if((pid = fork())!=0){
        waitpid(pid, &status, 0);
        close(client_sock);
        return;
    }

    /*connect to requested server using the official host*/
    if((server_sock = my_open_clientfd(host_cache->hostentry, port)) < 0){
        create_error_response(response_buff, 404, "Not Found");
        Rio_writen(client_sock, response_buff, strlen(response_buff));
        fprintf(stderr, "%s", response_buff);
        close(client_sock);
        exit(0);     
    }   
    pid_t pid2;
    if((pid2 = fork())==0){
        rio_t rio_server;
        Rio_readinitb(&rio_server, server_sock);        
        char response_line[MAXLINE];

        Rio_readlineb(&rio_server, response_line, MAXLINE);
        
        Rio_writen(client_sock, response_line, strlen(response_line));
        
        /*read from server then write to client*/
        char c;
        fprintf(stderr, "%s", response_line);
        while(Rio_readnb(&rio_server, &c, 1) > 0  && c!=EOF){
            Rio_writen(client_sock, &c, 1);
            fprintf(stderr, "%c", c);       
        }
        close(client_sock);
        close(server_sock);
        exit(0);
    }

    char request_line[MAXLINE];    
    sprintf(request_line, "GET /%s %s", path_buff, version_buff);
    /*send request to server*/
    Rio_writen(server_sock, request_line, strlen(request_line)); 
    fprintf(stderr, "%s", request_line);
    char c;
    while(Rio_readnb(&rio_client, &c, 1) > 0 && c!=EOF){
        /*read from client and write to server*/
        Rio_writen(server_sock, &c, 1); 
        fprintf(stderr, "%c", c); 
    }
    fprintf(stderr,"FINISHED CONNECTION");    
    waitpid(pid2, &status, 0);
    close(client_sock);
    close(server_sock);
    exit(0);
}


int get_uri(char *request_buff, char *uri_buff, char *version_buff){
    /*request is null*/
    if(request_buff == NULL)
        return -1;
    /*tokenize the request line on whitespace*/
    char *get = strtok(request_buff, " ");
    char *uri = strtok(NULL, " ");
    char *version = strtok(NULL, " ");

    /*check none of the above is null*/
    if(get == NULL || uri == NULL || version == NULL){
        return -1;
    }

    /*copy uri and version to buffer*/
    strncpy(uri_buff,uri,strlen(uri));
    /*this is added because strpbrk does not search terminating null-character*/
    /*needed for parse_uri to parse correctly*/
    char *hostend = strpbrk(uri_buff, "/");
    if(hostend == NULL)
        strncat(uri_buff, "/", 1);
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


