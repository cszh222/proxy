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

struct DNScache{
    char *hostname;
    struct hostent *hostentry;
    struct DNScache *next;
};

struct pageCache{
    char *full_uri;
    char *filename;
    struct pageCache *next;
};

struct pageCache *pageCacheStart;
struct DNScache *DNSListStart;

/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path, int  *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);
void handle_request(int client_sock, struct sockaddr *address);
int get_uri(char *request_buff, char *method_buff, char *uri_buff, char *version_buff);
int get_status(char *first_response);
void create_error_response(char* response_buff, int status, char* status_message);
struct DNScache* find_cache_in_list(char* host_name);
struct DNScache* add_cache_to_list(char* host_name);
int my_open_clientfd(struct hostent *cached_host_entry, int port);
struct pageCache* find_page_cache(char *uri);
struct pageCache* create_page_cache(char *uri);
int open_existing_page_cache(struct pageCache *cache_entry);
int open_new_page_cache(struct pageCache *cache_entry, char *hostname);
void write_to_log(char* logstring, int size, bool dns_cached, bool page_cached, bool not_found);
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

    /*seed for random number needed later*/
    srand(time(NULL));

    /*loop infinitely waiting on client*/
    while(1)
    {   
        int client_sock;
        struct sockaddr addr;
        socklen_t socklen; 
       
        /* Wait for a connection. */
        client_sock = Accept(proxy_sock, &addr, &socklen);

        handle_request(client_sock, &addr);

        pid_t pid = 1;
        while(pid > 0){
            pid = waitpid(-1, NULL, WNOHANG);
        }      
    }

    exit(0);
}

void handle_request(int client_sock, struct sockaddr *address){
    /*buffers*/
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
    char method_buff[MAXLINE];
    bzero(method_buff, MAXLINE);
    char response_buff[MAXLINE];
    bzero(response_buff, MAXLINE);

    /*flags for dns_cache and page cache*/
    bool dns_cached = false;
    bool page_cached = false;
    bool not_found = false;

    /* initialize rio for client*/
    rio_t rio_client;
    Rio_readinitb(&rio_client, client_sock);

    /*read first line*/
    ssize_t read_size;
    read_size = Rio_readlineb(&rio_client, (void *)request_buff, (size_t)MAXLINE);

    /*check that request isnt empty*/
    if(read_size <= 0)
        return;

    /*get the uri from request*/
    if(get_uri(request_buff, method_buff, uri_buff, version_buff) == -1){
        /* Bad request, send back error message*/
        create_error_response(response_buff, 400, "Bad Request");
        Rio_writen(client_sock, response_buff, strlen(response_buff));
        close(client_sock);
        return;      
    }

    /*chech that it is a get request, only allow get methods*/
    if(strncmp(method_buff, "GET", 3)!=0){
        close(client_sock);
        return;
    }

    int port;
    /*parse the uri*/
    if(parse_uri(uri_buff, host_buff, path_buff, &port) == -1){
        /* Invalid uri, send back error message*/
        create_error_response(response_buff, 400, "Bad Request");
        Rio_writen(client_sock, response_buff, strlen(response_buff));
        close(client_sock); 
        return;      
    }/*have separated uri into host, path and port*/

    struct DNScache *host_cache = find_cache_in_list(host_buff);
    if(host_cache == NULL)
        host_cache = add_cache_to_list(host_buff);
    else{
        dns_cached = true;
        fprintf(stderr,"********************DNS CAN BE LOADED FROM CACHE*********************\n");
    }

    int cache_fd;
    int server_sock;
    /*see if page is in cache*/
    struct pageCache *page_cache = find_page_cache(uri_buff);
    if(page_cache == NULL){
        page_cache = create_page_cache(uri_buff);
        cache_fd = open_new_page_cache(page_cache, host_cache->hostname);

        if((server_sock = my_open_clientfd(host_cache->hostentry, port)) < 0){
            create_error_response(response_buff, 404, "Not Found");
            Rio_writen(client_sock, response_buff, strlen(response_buff));
            close(client_sock);
            return;     
        }
    }
    else{
        page_cached = true;
        cache_fd = open_existing_page_cache(page_cache);
        fprintf(stderr,"********************PAGE CAN BE LOADED FROM CACHE********************\n");
    }    

    /*has loaded page cache and DNS cache, now fork*/
    pid_t pid = Fork();
    if(pid != 0){
        Close(client_sock);        
        Close(cache_fd);
        if(!page_cached)
            Close(server_sock);
        return;
    }

    /*page is not cached, read from server*/
    if(!page_cached){       

        /*write first line of request to server*/
        snprintf(request_buff, MAXLINE, "GET /%s HTTP/1.0\r\n", path_buff);    
        Rio_writen(server_sock, request_buff, strlen(request_buff)); 

        while((read_size = Rio_readlineb(&rio_client, (void *)request_buff, (size_t)MAXLINE)) > 0){
            Rio_writen(server_sock, request_buff, read_size);
            
            if(strncmp(request_buff, "\r\n", 2) == 0)
                break;
            
        }/*request has been sent*/
        fprintf(stderr,"********************FINISHED SENDING FULL REQUEST TO SERVER**********\n");

        /*initialize rio for server*/
        rio_t rio_server;
        Rio_readinitb(&rio_server, server_sock);
        
        ssize_t write_size;
        char first_line[MAXLINE];
        /*read first line*/        
        write_size = Rio_readlineb(&rio_server, (void *)first_line, (size_t)MAXLINE);
        strncpy(response_buff, first_line, write_size);

        int status;
        /*get the status*/
        status = get_status(first_line);
        if(status == 404)
            not_found = true;
        
        /*write first line to client and cache*/
        Rio_writen(client_sock, response_buff, write_size);
        Rio_writen(cache_fd, response_buff, write_size);

        timer_t start = (timer_t) time(NULL);
        timer_t end;
        /*write rest to client and cache*/
        while((read_size = Rio_readlineb(&rio_server,(void *)response_buff, (size_t)MAXLINE)) > 0){
            write_size += read_size;
            Rio_writen(client_sock, response_buff, read_size);
            Rio_writen(cache_fd, response_buff, read_size);

            //stop sending after 15 seconds
            end = (timer_t) time(NULL);
            if((end - start) >=15)
                break;
        }
        fprintf(stderr,"********************FINISHED WRITING TO CLIENT FROM SERVER***********\n");
        Close(client_sock);
        Close(cache_fd);
        Close(server_sock);

        char logstring[MAXLINE];
        format_log_entry(logstring, (struct sockaddr_in*) address, uri_buff, write_size);
        write_to_log(logstring, write_size, dns_cached, page_cached, not_found);

        exit(0);
    }

    ssize_t write_size = 0;
    /*create a rio_t for cache file*/
    rio_t rio_cache;
    Rio_readinitb(&rio_cache, cache_fd);

    while((read_size = Rio_readlineb(&rio_cache, response_buff, MAXLINE)) > 0){
        write_size += read_size;
        Rio_writen(client_sock, response_buff, read_size);
    }
    
    fprintf(stderr,"********************FINISHED WRITING TO CLIENT FROM CACHE*************\n");
    Close(client_sock);
    Close(cache_fd);    

    char logstring[MAXLINE];
    format_log_entry(logstring, (struct sockaddr_in*) address, uri_buff, write_size);
    write_to_log(logstring, write_size, dns_cached, page_cached, not_found);

    exit(0);    

}

void write_to_log(char* logstring, int size, bool dns_cached, bool page_cached, bool not_found){
    int fd;
    char size_buff[MAXLINE];
    char log_buff[MAXLINE];
    
    strncpy(log_buff, logstring, strlen(logstring));
    /*append to log_buff*/
    if(not_found)
        strncat(log_buff, " (NOT FOUND)", strlen(" (NOT FOUND)"));
    else{
        sprintf(size_buff, " %d", size);
        strncat(log_buff, size_buff, strlen(size_buff));
        if(dns_cached)
            strncat(log_buff, " (HOSTNAME CACHED)", strlen(" (HOSTNAME CACHED)"));
        if(page_cached)
            strncat(log_buff, " (PAGE CACHED)", strlen(" (PAGE CACHED)"));
    }
    strncat(log_buff, "\n", 1);

    fd = Open("./proxy.log", O_WRONLY | O_APPEND | O_CREAT,
     S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    Write(fd, log_buff, strlen(log_buff));

    Close(fd);
}

int open_existing_page_cache(struct pageCache *cache_entry){
    int fd;
    fd = Open(cache_entry->filename, O_RDONLY, 
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    return fd;
}

int open_new_page_cache(struct pageCache *cache_entry, char *hostname){
    int fd;
    char file_path[MAXLINE];
    char random[MAXLINE];
    snprintf(random, MAXLINE, "%d", rand());
    strcpy(file_path, "cache/");
    strncat(file_path, hostname, strlen(hostname));
    strncat(file_path, random, strlen(random));
    cache_entry->filename = strdup(file_path);
    fd = Open(file_path, 
        O_WRONLY | O_CREAT | O_TRUNC, 
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    return fd;
}

struct pageCache* find_page_cache(char *uri){
    if(pageCacheStart == NULL)
        return NULL;
    struct pageCache *cur_cache = pageCacheStart;
    struct pageCache *found_cache = NULL;

    do {
        if(strcmp(cur_cache->full_uri, uri) == 0){
            found_cache = cur_cache;
            break;
        }
    }while((cur_cache = cur_cache->next) != NULL);
    return found_cache;
}

struct pageCache* create_page_cache(char *uri){
    struct pageCache *new_cache = (struct pageCache*)malloc(sizeof(struct pageCache));
    new_cache->full_uri = strdup(uri);
    new_cache->filename = NULL;
    new_cache->next = NULL;

    if(pageCacheStart == NULL){
        pageCacheStart = new_cache;
        return new_cache;
    }
    /*iterate to back of list*/
    struct pageCache *cur_cache = pageCacheStart;
    while(cur_cache->next != NULL)
       cur_cache = cur_cache->next;
    cur_cache->next = new_cache;

    return new_cache;
}
int get_status(char *first_response){
    char *status_str;
    int status;
    /*get the status from the respnse*/
    strtok(first_response, " ");
    status_str = strtok(NULL, " ");

    status = atoi(status_str);

    return status;
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

    strncpy(version_buff,version,strlen(version));

    return 0;
}

void create_error_response(char* response_buff, int status, char* status_message){
    char response_body[MAXLINE];
    char response_header[MAXLINE];
    
    //create error response body
    snprintf(response_body, MAXLINE,
        "<html><head><title>%s</title></head><body>%d %s</body></html>",
        status_message, status, status_message);

    //create error response header
    snprintf(response_header, MAXLINE,
        "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d",
        status, status_message, strlen(response_body));

    snprintf(response_buff, MAXLINE, "%s\r\n\r\n%s", response_header, response_body);

    return;
}

struct DNScache* find_cache_in_list(char* host_name){
    if(DNSListStart == NULL)
        return NULL;
    struct DNScache *cur_cache = DNSListStart;
    struct DNScache *found_cache = NULL;

    do {
        if(strcmp(cur_cache->hostname, host_name) == 0){
            found_cache = cur_cache;
            break;
        }
    }while((cur_cache = cur_cache->next) != NULL);
    return found_cache;
}

struct DNScache* add_cache_to_list(char* host_name){
    struct DNScache *new_cache = (struct DNScache*)malloc(sizeof(struct DNScache));
    new_cache->hostname = strdup(host_name);

    struct hostent *new_hostent = Gethostbyname(host_name);
    new_cache->hostentry = new_hostent;
    new_cache->next = NULL;

    if(DNSListStart == NULL){
        DNSListStart = new_cache;
        return new_cache;
    }
    /*iterate to back of list*/
    struct DNScache *cur_cache = DNSListStart;
    while(cur_cache->next != NULL)
       cur_cache = cur_cache->next;
    cur_cache->next = new_cache;

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
