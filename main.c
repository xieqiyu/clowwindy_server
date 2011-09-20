#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include "main.h"

#define STATUS_READ_REQUEST_HEADER	0
#define STATUS_SEND_RESPONSE_HEADER	1
#define STATUS_SEND_RESPONSE		2

#define header_404 "HTTP/1.1 404 Not found\r\nServer: myserver/1.0\r\nContent-Type: text/html\r\n\r\n<h1>not found</h1>"
#define header_200 "HTTP/1.1 200 OK\r\nServer: myserver/1.0\r\nContent-Type: text/html\r\n\r\n"


static struct process_t processes[MAX_PORCESS];

static int listen_sock;
static int efd;
static struct epoll_event event;

int setNonblocking(int fd)
{
    int flags;

    /* If they have O_NONBLOCK, use the Posix way to do it */
#if defined(O_NONBLOCK)
    /* Fixme: O_NONBLOCK is defined but broken on SunOS 4.1.x and AIX 3.2.5. */
    if (-1 == (flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#else
    /* Otherwise, use the old way of doing it */
    flags = 1;
    return ioctl(fd, FIOBIO, &flags);
#endif
}

struct process_t* find_process_by_sock(int sock) {
    int i;
    for (i=0;i<MAX_PORCESS;i++) {
        if (processes[i].sock == sock) {
            return &processes[i];
        }
    }
    return 0;
}

void reset_process(struct process_t* process)
{
    process->read_pos = 0;
    process->write_pos = 0;
}


struct process_t* accept_sock(int listen_sock) {
    int s;
    // 在ET模式下必须循环accept到返回-1为止
    while (1)
    {
        struct process_t* process = find_process_by_sock(-1);
        if (process == 0) {
            // 请求已满
            return;
        }
        struct sockaddr in_addr;
        socklen_t in_len;
        int infd;
        char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

        in_len = sizeof in_addr;
        infd = accept (listen_sock, &in_addr, &in_len);
        if (infd == -1)
        {
            if ((errno == EAGAIN) ||
                    (errno == EWOULDBLOCK))
            {
                /* We have processed all incoming
                   connections. */
                break;
            }
            else
            {
                perror ("accept");
                break;
            }
        }

        getnameinfo (&in_addr, in_len,
                     hbuf, sizeof hbuf,
                     sbuf, sizeof sbuf,
                     NI_NUMERICHOST | NI_NUMERICSERV);
        /* Make the incoming socket non-blocking and add it to the
           list of fds to monitor. */
        s = setNonblocking (infd);
        if (s == -1)
            abort ();

        //添加监视sock的读取状态
        event.data.fd = infd;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (efd, EPOLL_CTL_ADD, infd, &event);
        if (s == -1)
        {
            perror ("epoll_ctl");
            abort ();
        }
        // slow, unneccessary
// 	memset(process,0,sizeof(struct process_t));
        reset_process(process);
        process->sock = infd;
        process->status = STATUS_READ_REQUEST_HEADER;
    }
}

void read_request(struct process_t* process) {
    int sock = process->sock, s;
    char* buf=process->buf;
    char read_complete = 0;

    ssize_t count;

    while (1) {
        count = read (sock, buf + process->read_pos, BUF_SIZE - process->read_pos);
        if (count == -1)
        {
            if (errno != EAGAIN)
            {
                handle_error (process, "read request");
                return;
            } else {
                //errno == EAGAIN表示读取完毕
                break;
            }
        }
        else if (count == 0)
        {
            // 被客户端关闭连接，这不应该发生
            handle_error (process, "connection closed by client");
            return;
        } else if (count > 0) {
            process->read_pos += count;
        }
    }

    // determine whether the request is complete
    buf[process->read_pos]=0;
    read_complete = (strstr(buf, "\n\n") != 0) || (strstr(buf, "\r\n\r\n") != 0);

    int error = 0;
    if (read_complete) {
	//重置读取位置
	reset_process(process);
        // get GET info
        if (strncmp(buf, "GET", 3) == 0) {
            // get first line
            int n_loc = (int)strchr(buf, '\n');
            int space_loc = (int)strchr(buf + 4, ' ');
            if (n_loc > space_loc) {
                char path[255];
                int len = space_loc - (int)buf - 4;
                strncpy(path, buf+4, len);
                path[len] = 0;
                //                             printf("path: %s\n", path);
                //                             printf("\n");

                char fullname[256];
                char *prefix = DOC_ROOT;
                strcpy(fullname, prefix);
                strcpy(fullname + strlen(prefix), path);
                int fd = open(fullname, O_RDONLY);
                process->fd = fd;
                if (fd<0) {
                    process->response_code = 404;
                } else {
                    process->response_code = 200;
                }
                process->status = STATUS_SEND_RESPONSE_HEADER;
                //修改此sock的监听状态，改为监视写状态
                event.data.fd = process->sock;
                event.events = EPOLLOUT | EPOLLET;
                s = epoll_ctl (efd, EPOLL_CTL_MOD, process->sock, &event);
                if (s == -1)
                {
                    perror ("epoll_ctl");
                    abort ();
                }
                send_response_header(process);
            } else {
                error = 400;
            }

        } else {
            error = 401;
        }
    }
}


int write_all(struct process_t *process, char* buf, int n) {
    int done_write = 0;
    int total_bytes_write = 0;
    while (!done_write && total_bytes_write != n) {
        int bytes_write = write(process->sock, buf + total_bytes_write, n - total_bytes_write);
// 	printf("bytes_write: %d\n", bytes_write);
        if (bytes_write == -1) {
            if (errno != EAGAIN)
            {
                handle_error (process, "write");
                return 0;
            } else {
                // 写入到缓冲区已满了
                return total_bytes_write;
            }
        } else {
            total_bytes_write += bytes_write;
        }
    }
    return total_bytes_write;
}


void send_response_header(struct process_t *process) {
    if (process->response_code != 200) {
        int bytes_writen = write_all(process, header_404+process->write_pos, strlen(header_404)-process->write_pos);
        if (bytes_writen == strlen(header_404) + process->write_pos) {
            // 写入完毕
            cleanup(process);
        } else {
            process->write_pos += bytes_writen;
        }
    } else {
        int bytes_writen = write_all(process, header_200+process->write_pos, strlen(header_200)-process->write_pos);
        if (bytes_writen == strlen(header_200) + process->write_pos) {
            // 写入完毕
            process->status = STATUS_SEND_RESPONSE;
            send_response(process);
        } else {
            process->write_pos += bytes_writen;
        }
    }
}

void send_response(struct process_t *process) {
    //文件已经读完
    char end_of_file = 0;
    while (1) {
        //检查有无已读取还未写入的
        int size_remaining = process->read_pos - process->write_pos;
        if (size_remaining > 0) {
            // 写入
            int bytes_writen = write_all(process, process->buf+process->write_pos, size_remaining);
            process->write_pos += bytes_writen;
            // 接下来判断是否写入完毕，如果是，继续读文件，否则return
            if (bytes_writen != size_remaining) {
                // 缓冲区满
                return;
            }
        }
        if (end_of_file) {
                //读写完毕，关闭sock和文件
                cleanup(process);
                return;
        }
        //读取文件
        int done = 0;
        //用同步的方式读取到缓冲区满
        process -> read_pos = 0;
        process -> write_pos = 0;
        while (process->read_pos < BUF_SIZE) {
            int bytes_read = read(process->fd, process->buf, BUF_SIZE - process->read_pos);
            if (bytes_read == -1)
            {
                if (errno != EAGAIN)
                {
                    handle_error(process, "read file");
                    return;
                }
                break;
            }
            else if (bytes_read == 0)
            {
                end_of_file = 1;
                break;
            } else if (bytes_read > 0) {
                process->read_pos += bytes_read;
            }
        }
    }

}

void cleanup(struct process_t *process) {
    close(process->fd);
    close(process->sock);
    process->sock = -1;
    reset_process(process);
}

void handle_error(struct process_t* process, char* error_string)
{
    cleanup(process);
    perror(error_string);
}


void handle_request(int sock) {
    if (sock == listen_sock) {
        accept_sock(sock);
    } else {
        struct process_t* process = find_process_by_sock(sock);
        if (process != 0) {
            switch (process->status) {
            case STATUS_READ_REQUEST_HEADER:
                read_request(process);
                break;
            case STATUS_SEND_RESPONSE_HEADER:
                send_response_header(process);
                break;
            case STATUS_SEND_RESPONSE:
                send_response(process);
                break;
            default:
                break;
            }
        }
    }
}

static int
create_and_bind (char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
    hints.ai_flags = AI_PASSIVE;     /* All interfaces */

    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0)
    {
        fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        listen_sock = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        if (listen_sock == -1)
            continue;

        s = bind (listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
        {
            /* We managed to bind successfully! */
            break;
        }

        close (listen_sock);
    }

    if (rp == NULL)
    {
        fprintf (stderr, "Could not bind\n");
        return -1;
    }

    freeaddrinfo (result);

    return listen_sock;
}

void init_processes() {
  int i = 0;
  for(;i < MAX_PORCESS; i ++) {
    processes[i].sock = -1;
  }
  
}

int
main (int argc, char *argv[])
{
    int s;
    struct epoll_event *events;

    if (argc != 2)
    {
        fprintf (stderr, "Usage: %s [port]\n", argv[0]);
        exit (EXIT_FAILURE);
    }
    
    init_processes();

    listen_sock = create_and_bind (argv[1]);
    if (listen_sock == -1)
        abort ();

    s = setNonblocking (listen_sock);
    if (s == -1)
        abort ();

    s = listen (listen_sock, SOMAXCONN);
    if (s == -1)
    {
        perror ("listen");
        abort ();
    }

    efd = epoll_create1 (0);
    if (efd == -1)
    {
        perror ("epoll_create");
        abort ();
    }

    event.data.fd = listen_sock;
    event.events = EPOLLIN | EPOLLET;
    s = epoll_ctl (efd, EPOLL_CTL_ADD, listen_sock, &event);
    if (s == -1)
    {
        perror ("epoll_ctl");
        abort ();
    }

    /* Buffer where events are returned */
    events = calloc (MAXEVENTS, sizeof event);

    /* The event loop */
    while (1)
    {
        int n, i;

        n = epoll_wait (efd, events, MAXEVENTS, -1);
        for (i = 0; i < n; i++)
        {
            if ((events[i].events & EPOLLERR) ||
                    (events[i].events & EPOLLHUP))
            {
                /* An error has occured on this fd, or the socket is not
                   ready for reading (why were we notified then?) */
                fprintf (stderr, "epoll error\n");
                close (events[i].data.fd);
                continue;
            }

            handle_request(events[i].data.fd);

        }
    }

    free (events);

    close (listen_sock);

    return EXIT_SUCCESS;
}
