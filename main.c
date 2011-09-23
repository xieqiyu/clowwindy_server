#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <langinfo.h>
#include <locale.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifdef USE_SENDFILE
#include <sys/sendfile.h>
#endif

#include "main.h"

#define STATUS_READ_REQUEST_HEADER	0
#define STATUS_SEND_RESPONSE_HEADER	1
#define STATUS_SEND_RESPONSE		2

#define NO_SOCK -1
#define NO_FILE -1

#define RFC1123_DATE_FMT "%a, %d %b %Y %H:%M:%S %Z"

#define header_404 "HTTP/1.1 404 Not Found\r\nServer: clowwindyserver/1.0\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n<h1>Not found</h1>"
#define header_400 "HTTP/1.1 400 Bad Request\r\nServer: clowwindyserver/1.0\r\nContent-Type: text/html\r\nConnection: Close\r\n\r\n<h1>Bad request</h1>"
#define header_200_start "HTTP/1.1 200 OK\r\nServer: clowwindyserver/1.0\r\nContent-Type: text/html\r\nConnection: Close\r\n"
#define header_304_start "HTTP/1.1 304 Not Modified\r\nServer: clowwindyserver/1.0\r\nContent-Type: text/html\r\nConnection: Close\r\n"

#define header_end "\r\n"

#define HEADER_IF_MODIFIED_SINCE "If-Modified-Since: "

#define write_to_header(string_to_write) strcpy(process->buf + strlen(process->buf), string_to_write)


static struct process processes[MAX_PORCESS];

static int listen_sock;
static int efd;
static struct epoll_event event;
static char *doc_root;
static int current_total_processes;

int setNonblocking ( int fd )
{
    int flags;

    /* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
    /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
    if ( -1 == ( flags = fcntl ( fd, F_GETFL, 0 ) ) )
        flags = 0;
    return fcntl ( fd, F_SETFL, flags | O_NONBLOCK );
#else
    /* Otherwise, use the old way of doing it */
    flags = 1;
    return ioctl ( fd, FIOBIO, &flags );
#endif
}

// 遍历查找，慢
struct process* find_process_by_sock_slow ( int sock )
{
    int i;
    for ( i=0;i<MAX_PORCESS;i++ )
    {
        if ( processes[i].sock == sock )
        {
            return &processes[i];
        }
    }
    return 0;
}

struct process* find_empty_process_for_sock ( int sock )
{
    if ( sock < MAX_PORCESS && sock >= 0 && processes[sock].sock == NO_SOCK )
    {
        return &processes[sock];
    }
    else
    {
        return find_process_by_sock_slow ( NO_SOCK );
    }
}

struct process* find_process_by_sock ( int sock )
{
    if ( sock < MAX_PORCESS && sock >= 0 && processes[sock].sock == sock )
    {
        return &processes[sock];
    }
    else
    {
        return find_process_by_sock_slow ( sock );
    }
}

void reset_process ( struct process* process )
{
    process->read_pos = 0;
    process->write_pos = 0;
}


struct process* accept_sock ( int listen_sock )
{
    int s;
    // 在ET模式下必须循环accept到返回-1为止
    while ( 1 )
    {
        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;
        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
        if ( current_total_processes >= MAX_PORCESS )
        {
            // 请求已满，accept之后直接挂断
            infd = accept ( listen_sock, &in_addr, &in_len );
            if ( infd == -1 )
            {
                if ( ( errno == EAGAIN ) ||
                        ( errno == EWOULDBLOCK ) )
                {
                    /* We have processed all incoming
                      connections. */
                    break;
                }
                else
                {
                    perror ( "accept" );
                    break;
                }
            }
            close ( infd );

            return;
        }

        in_len = sizeof in_addr;
        infd = accept ( listen_sock, &in_addr, &in_len );
        if ( infd == -1 )
        {
            if ( ( errno == EAGAIN ) ||
                    ( errno == EWOULDBLOCK ) )
            {
                /* We have processed all incoming
                   connections. */
                break;
            }
            else
            {
                perror ( "accept" );
                break;
            }
        }

        getnameinfo ( &in_addr, in_len,
                      hbuf, sizeof hbuf,
                      sbuf, sizeof sbuf,
                      NI_NUMERICHOST | NI_NUMERICSERV );
        /* Make the incoming socket non-blocking and add it to the
           list of fds to monitor. */
        s = setNonblocking ( infd );
        if ( s == -1 )
            abort ();
        int on = 1;
        setsockopt ( infd, SOL_TCP, TCP_CORK, &on, sizeof ( on ) );
        //添加监视sock的读取状态
        event.data.fd = infd;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl ( efd, EPOLL_CTL_ADD, infd, &event );
        if ( s == -1 )
        {
            perror ( "epoll_ctl" );
            abort ();
        }
        struct process* process = find_empty_process_for_sock ( infd );
        current_total_processes++;
        reset_process ( process );
        process->sock = infd;
        process->fd = NO_FILE;
        process->status = STATUS_READ_REQUEST_HEADER;
    }
}

// 根据目录名自动添加index.htm
int get_index_file ( char *filename_buf, struct stat *pstat )
{
    struct stat stat_buf;
    int s;
    s = lstat ( filename_buf, &stat_buf );
    if ( s == -1 )
    {
        // 文件或目录不存在
        return -1;
    }
    if ( S_ISDIR ( stat_buf.st_mode ) )
    {
        // 是目录，追加index.htm(l)
        strcpy ( filename_buf + strlen ( filename_buf ), INDEX_FILE );
        // 再次判断是否是文件
        s = lstat ( filename_buf, &stat_buf );
        if ( s == -1 || S_ISDIR ( stat_buf.st_mode ) )
        {
            // 文件不存在，或者为目录
            int len = strlen ( filename_buf );
            filename_buf[len] = 'l';
            filename_buf[len + 1] = 0;
            s = lstat ( filename_buf, &stat_buf );
            if ( s == -1 || S_ISDIR ( stat_buf.st_mode ) )
            {
                // 文件不存在，或者为目录
                return -1;
            }
        }
    }
    *pstat = stat_buf;
    return 0;
}

void read_request ( struct process* process )
{
    int sock = process->sock, s;
    char* buf=process->buf;
    char read_complete = 0;

    ssize_t count;

    while ( 1 )
    {
        count = read ( sock, buf + process->read_pos, BUF_SIZE - process->read_pos );
        if ( count == -1 )
        {
            if ( errno != EAGAIN )
            {
                handle_error ( process, "read request" );
                return;
            }
            else
            {
                //errno == EAGAIN表示读取完毕
                break;
            }
        }
        else if ( count == 0 )
        {
            // 被客户端关闭连接
            cleanup ( process );
            return;
        }
        else if ( count > 0 )
        {
            process->read_pos += count;
        }
    }

    int header_length = process->read_pos;
    // determine whether the request is complete
    if ( header_length > BUF_SIZE - 1 )
    {
	process->response_code = 400;
	process->status = STATUS_SEND_RESPONSE_HEADER;
	strcpy ( process->buf, header_400 );
	send_response_header ( process );
	handle_error ( processes, "bad request" );
	return;
    }
    buf[header_length]=0;
    read_complete = ( strstr ( buf, "\n\n" ) != 0 ) || ( strstr ( buf, "\r\n\r\n" ) != 0 );

    int error = 0;
    if ( read_complete )
    {
        //重置读取位置
        reset_process ( process );
        // get GET info
        if ( !strncmp ( buf, "GET", 3 ) == 0 )
        {
            process->response_code = 400;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_400 );
            send_response_header ( process );
            handle_error ( processes, "bad request" );
            return;
        }
        // get first line
        int n_loc = ( int ) strchr ( buf, '\n' );
        int space_loc = ( int ) strchr ( buf + 4, ' ' );
        if ( n_loc <= space_loc )
        {
            process->response_code = 400;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_400 );
            send_response_header ( process );
            handle_error ( processes, "bad request" );
            return;
        }
        char path[255];
        int len = space_loc - ( int ) buf - 4;
        if ( len > MAX_URL_LENGTH )
        {
            process->response_code = 400;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_400 );
            send_response_header ( process );
            handle_error ( processes, "bad request" );
            return;
        }
        buf[header_length] = 0;
        strncpy ( path, buf+4, len );
        path[len] = 0;

        struct stat filestat;
        char fullname[256];
        char *prefix = doc_root;
        strcpy ( fullname, prefix );
        strcpy ( fullname + strlen ( prefix ), path );
        s = get_index_file ( fullname, &filestat);
        if ( s == -1 )
        {
            process->response_code = 404;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_404 );
            send_response_header ( process );
            handle_error ( processes, "not found" );
            return;
        }

        int fd = open ( fullname, O_RDONLY );

        process->fd = fd;
        if ( fd<0 )
        {
            process->response_code = 404;
            process->status = STATUS_SEND_RESPONSE_HEADER;
            strcpy ( process->buf, header_404 );
            send_response_header ( process );
            handle_error ( processes, "not found" );
            return;
        }
        else
        {
            process->response_code = 200;
        }
	
        char tempstring[256];

        //检查有无If-Modified-Since，返回304
        char* c = strstr ( buf, HEADER_IF_MODIFIED_SINCE );
	if(c!=0){
	    char* rn = strchr(c, '\r');
	    if(rn==0){
	      rn = strchr(c, '\n');
	      if(rn==0){
		  process->response_code = 400;
		  process->status = STATUS_SEND_RESPONSE_HEADER;
		  strcpy ( process->buf, header_400 );
		  send_response_header ( process );
		  handle_error ( processes, "bad request" );
		  return;
	      }
	    }
	  int time_len = rn - c - sizeof(HEADER_IF_MODIFIED_SINCE) + 1;
	  strncpy(tempstring, c + sizeof(HEADER_IF_MODIFIED_SINCE) - 1,time_len);
	  tempstring[time_len]=0;
	  {
	    struct tm tm;
	    time_t t;
	    strptime(tempstring, RFC1123_DATE_FMT, &tm);
	    tzset();
	    t=mktime(&tm);
	    t-=timezone;
	    gmtime_r(&t, &tm);
	    if(t >= filestat.st_mtime){
	      process->response_code = 304;
	    }
	  }
	}

        //开始header
        process->buf[0] = 0;
	if(process->response_code == 304){
	  write_to_header ( header_304_start );
	} else {
	  write_to_header ( header_200_start );
	}

        process->total_length = filestat.st_size;

	{
	  //写入当前时间
	  struct tm *tm;
	  time_t tmt;
	  tmt = time ( NULL );
	  tm = gmtime ( &tmt );
	  strftime ( tempstring, sizeof ( tempstring ), RFC1123_DATE_FMT, tm );
	  write_to_header ( "Date: " );
	  write_to_header ( tempstring );
	  write_to_header ( "\r\n" );

	  //写入文件修改时间
	  tm = gmtime ( &filestat.st_mtime );
	  strftime ( tempstring, sizeof ( tempstring ), RFC1123_DATE_FMT, tm );
	  write_to_header ( "Last-modified: " );
	  write_to_header ( tempstring );
	  write_to_header ( "\r\n" );

	  if(process->response_code == 200){
	    //写入content长度
	    sprintf ( tempstring, "Content-Length: %ld\r\n", filestat.st_size );
	    write_to_header ( tempstring );
	  }
	}

        //结束header
        write_to_header ( header_end );

        process->status = STATUS_SEND_RESPONSE_HEADER;
        //修改此sock的监听状态，改为监视写状态
        event.data.fd = process->sock;
        event.events = EPOLLOUT | EPOLLET;
        s = epoll_ctl ( efd, EPOLL_CTL_MOD, process->sock, &event );
        if ( s == -1 )
        {
            perror ( "epoll_ctl" );
            abort ();
        }
        //发送header
        send_response_header ( process );
    }
}


int write_all ( struct process *process, char* buf, int n )
{
    int done_write = 0;
    int total_bytes_write = 0;
    while ( !done_write && total_bytes_write != n )
    {
        int bytes_write = write ( process->sock, buf + total_bytes_write, n - total_bytes_write );
        if ( bytes_write == -1 )
        {
            if ( errno != EAGAIN )
            {
                handle_error ( process, "write" );
                return 0;
            }
            else
            {
                // 写入到缓冲区已满了
                return total_bytes_write;
            }
        }
        else
        {
            total_bytes_write += bytes_write;
        }
    }
    return total_bytes_write;
}


void send_response_header ( struct process *process )
{
    if ( process->response_code != 200 )
    {
	//非200不进入send_response
        int bytes_writen = write_all ( process, process->buf+process->write_pos, strlen ( process->buf )-process->write_pos );
        if ( bytes_writen == strlen ( process->buf ) + process->write_pos )
        {
            // 写入完毕
            cleanup ( process );
        }
        else
        {
            process->write_pos += bytes_writen;
        }
    }
    else
    {
        int bytes_writen = write_all ( process, process->buf+process->write_pos, strlen ( process->buf )-process->write_pos );
        if ( bytes_writen == strlen ( process->buf ) + process->write_pos )
        {
            // 写入完毕
            process->status = STATUS_SEND_RESPONSE;
            send_response ( process );
        }
        else
        {
            process->write_pos += bytes_writen;
        }
    }
}

void send_response ( struct process *process )
{
#ifdef USE_SENDFILE
    // 使用linux sendfile函数
    while ( 1 )
    {
        int s = sendfile ( process-> sock, process -> fd, &process->read_pos, process->total_length - process -> read_pos );
        if ( s == -1 )
        {
            if ( errno != EAGAIN )
            {
                handle_error ( process, "sendfile" );
                return;
            }
            else
            {
                // 写入到缓冲区已满了
                return;
            }
        }
        if ( process->read_pos == process->total_length )
        {
            // 读写完毕
            cleanup ( process );
            return;
        }
    }
#else
    //文件已经读完
    char end_of_file = 0;
    while ( 1 )
    {
        //检查有无已读取还未写入的
        int size_remaining = process->read_pos - process->write_pos;
        if ( size_remaining > 0 )
        {
            // 写入
            int bytes_writen = write_all ( process, process->buf+process->write_pos, size_remaining );
            process->write_pos += bytes_writen;
            // 接下来判断是否写入完毕，如果是，继续读文件，否则return
            if ( bytes_writen != size_remaining )
            {
                // 缓冲区满
                return;
            }
        }
        if ( end_of_file )
        {
            //读写完毕，关闭sock和文件
            cleanup ( process );
            return;
        }
        //读取文件
        int done = 0;
        //用同步的方式读取到缓冲区满
        process -> read_pos = 0;
        process -> write_pos = 0;
        while ( process->read_pos < BUF_SIZE )
        {
            int bytes_read = read ( process->fd, process->buf, BUF_SIZE - process->read_pos );
            if ( bytes_read == -1 )
            {
                if ( errno != EAGAIN )
                {
                    handle_error ( process, "read file" );
                    return;
                }
                break;
            }
            else if ( bytes_read == 0 )
            {
                end_of_file = 1;
                break;
            }
            else if ( bytes_read > 0 )
            {
                process->read_pos += bytes_read;
            }
        }
    }
#endif
}

void cleanup ( struct process *process )
{
    int s;
    if ( process->sock != NO_SOCK )
    {
        s = close ( process->sock );
        current_total_processes--;
        if ( s == NO_SOCK )
        {
            perror ( "close sock" );
        }
    }
    if ( process->fd != -1 )
    {
        s = close ( process->fd );
        if ( s == NO_FILE )
        {
            printf ( "fd: %d\n",process->fd );
            printf ( "\n" );
            perror ( "close file" );
        }
    }
    process->sock = NO_SOCK;
    reset_process ( process );
}

void handle_error ( struct process* process, char* error_string )
{
    cleanup ( process );
    perror ( error_string );
}


void handle_request ( int sock )
{
    if ( sock == listen_sock )
    {
        accept_sock ( sock );
    }
    else
    {
        struct process* process = find_process_by_sock ( sock );
        if ( process != 0 )
        {
            switch ( process->status )
            {
            case STATUS_READ_REQUEST_HEADER:
                read_request ( process );
                break;
            case STATUS_SEND_RESPONSE_HEADER:
                send_response_header ( process );
                break;
            case STATUS_SEND_RESPONSE:
                send_response ( process );
                break;
            default:
                break;
            }
        }
    }
}

static int create_and_bind ( char *port )
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset ( &hints, 0, sizeof ( struct addrinfo ) );
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    s = getaddrinfo ( NULL, port, &hints, &result );
    if ( s != 0 )
    {
        fprintf ( stderr, "getaddrinfo: %s\n", gai_strerror ( s ) );
        return -1;
    }

    for ( rp = result; rp != NULL; rp = rp->ai_next )
    {
        listen_sock = socket ( rp->ai_family, rp->ai_socktype, rp->ai_protocol );
        int opt = 1;
        setsockopt ( listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof ( opt ) );
        if ( listen_sock == -1 )
            continue;

        s = bind ( listen_sock, rp->ai_addr, rp->ai_addrlen );
        if ( s == 0 )
        {
            /* We managed to bind successfully! */
            break;
        }

        close ( listen_sock );
    }

    if ( rp == NULL )
    {
        fprintf ( stderr, "Could not bind\n" );
        return -1;
    }

    freeaddrinfo ( result );

    return listen_sock;
}

void init_processes()
{
    int i = 0;
    for ( ;i < MAX_PORCESS; i ++ )
    {
        processes[i].sock = NO_SOCK;
    }

}

void sighandler ( int sig )
{
    exit ( 0 );
}

int main ( int argc, char *argv[] )
{
    int s;
    struct epoll_event *events;

    signal ( SIGABRT, &sighandler );
    signal ( SIGTERM, &sighandler );
    signal ( SIGINT, &sighandler );

    if ( argc != 3 )
    {
        fprintf ( stderr, "Usage: %s [port] [doc root]\n", argv[0] );
        exit ( EXIT_FAILURE );
    }

    init_processes();

    listen_sock = create_and_bind ( argv[1] );
    doc_root = argv[2];
    if ( listen_sock == -1 )
        abort ();

    s = setNonblocking ( listen_sock );
    if ( s == -1 )
        abort ();

    s = listen ( listen_sock, SOMAXCONN );
    if ( s == -1 )
    {
        perror ( "listen" );
        abort ();
    }

    efd = epoll_create1 ( 0 );
    if ( efd == -1 )
    {
        perror ( "epoll_create" );
        abort ();
    }

    event.data.fd = listen_sock;
    event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl ( efd, EPOLL_CTL_ADD, listen_sock, &event );
    if ( s == -1 )
    {
        perror ( "epoll_ctl" );
        abort ();
    }

    /* Buffer where events are returned */
    events = calloc ( MAXEVENTS, sizeof event );

    /* The event loop */
    while ( 1 )
    {
        int n, i;

        n = epoll_wait ( efd, events, MAXEVENTS, -1 );
        if ( n == -1 )
        {
            perror ( "epoll_wait" );
        }
        for ( i = 0; i < n; i++ )
        {
            if ( ( events[i].events & EPOLLERR ) ||
                    ( events[i].events & EPOLLHUP ) )
            {
                /* An error has occured on this fd, or the socket is not
                   ready for reading (why were we notified then?) */
                fprintf ( stderr, "epoll error\n" );
                close ( events[i].data.fd );
                continue;
            }

            handle_request ( events[i].data.fd );

        }
    }

    free ( events );

    close ( listen_sock );

    return EXIT_SUCCESS;
}
