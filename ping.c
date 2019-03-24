/*_
 * Copyright (c) 2014,2019 Hirochika Asai <asai@jar.jp>
 * All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>

#define BUFFER_SIZE                     65536
#define ICMP_TYPE_ECHO_REQUEST          8
#define ICMP_TYPE_ECHO_REPLY            0
#define ICMPV6_TYPE_ECHO_REQUEST        128
#define ICMPV6_TYPE_ECHO_REPLY          129
#define PING_TIMEOUT                    10

struct ip_hdr {
    uint8_t verlen;
    uint8_t diffserv;
    uint16_t total_len;
    uint16_t ident;
    uint16_t offset;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t headerChecksum;
    uint8_t sourceAddress[4];
    uint8_t destinationAddress[4];
    // options...
    // data...
} __attribute__ ((packed));

struct icmp_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t ident;
    uint16_t seq;
    // data...
} __attribute__ ((packed));

struct icmp6_hdr {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    // data...
} __attribute__ ((packed));

/*
 * Linked list
 */
struct ping_entry {
    char *target;
    int family;
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    } u;
    uint16_t ident;
    uint16_t seq;
    double t0;
    struct ping_entry *next;
};

struct slping {
    struct ping_entry *head;
    struct ping_entry *tail;
    int sock4;
    int sock6;
    int curseq;
};

/*
 * Get current time in microtime
 */
double
microtime(void)
{
    struct timeval tv;
    double microsec;

    if ( 0 != gettimeofday(&tv, NULL) ) {
        return 0.0;
    }

    microsec = (double)tv.tv_sec + (1.0 * tv.tv_usec / 1000000);

    return microsec;
}

/*
 * Calculate checksum
 */
uint16_t
checksum(const uint8_t *buf, size_t len) {
    size_t nleft;
    int32_t sum;
    const uint16_t *cur;
    union {
        uint16_t us;
        uint8_t uc[2];
    } last;
    uint16_t ret;

    nleft = len;
    sum = 0;
    cur = (const uint16_t *)buf;

    while ( nleft > 1 ) {
        sum += *cur;
        cur += 1;
        nleft -= 2;
    }

    if ( 1 == nleft ) {
        last.uc[0] = *(const uint8_t *)cur;
        last.uc[1] = 0;
        sum += last.us;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    ret = ~sum;

    return ret;
}

/*
 * Clean ping queue
 */
static int
_gc(struct slping *slp)
{
    struct ping_entry *ent;
    double tm;

    tm = microtime();
    ent = slp->head;
    while ( NULL != ent ) {
        if ( ent->t0 + PING_TIMEOUT > tm ) {
            /* Not timeout, then keep this entry */
            break;
        }
        /* Timeout */
        printf("%s %d\n", ent->target, -1);
        fflush(stdout);
        free(ent->target);
        free(ent);
        ent = ent->next;
    }
    if ( NULL == ent ) {
        slp->tail = NULL;
    }
    slp->head = ent;

    return 0;
}

/*
 * Remove an entry
 */
static int
_remove_entry(struct slping *slp, struct ping_entry *e)
{
    struct ping_entry **ep;
    struct ping_entry *cur;

    ep = &slp->head;
    cur = NULL;
    while ( NULL != *ep ) {
        if ( *ep == e ) {
            /* Found */
            *ep = e->next;
            free(e->target);
            free(e);
        } else {
            cur = *ep;
            ep = &(*ep)->next;
        }
    }

    /* Update the tail */
    slp->tail = cur;

    return 0;
}

/*
 * Send an ICMP echo request
 */
static int
_ping_send(int family, int sock, struct addrinfo *dai, uint16_t ident,
           uint16_t seq, size_t sz, double *tm)
{
    ssize_t ret;
    uint8_t buf[BUFFER_SIZE];
    struct icmp_hdr *icmp;
    size_t pktsize;
    size_t i;

    /* Compute packet size */
    pktsize = sizeof(struct icmp_hdr) + sz;
    if ( pktsize > BUFFER_SIZE ) {
        return -1;
    }

    /* Build an ICMP packet */
    switch ( family ) {
    case AF_INET:
        icmp = (struct icmp_hdr *)buf;
        icmp->type = ICMP_TYPE_ECHO_REQUEST;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->ident = htons(ident);
        icmp->seq = htons(seq);
        break;
    case AF_INET6:
        icmp = (struct icmp_hdr *)buf;
        icmp->type = ICMPV6_TYPE_ECHO_REQUEST;
        icmp->code = 0;
        icmp->checksum = 0;
        icmp->ident = htons(ident);
        icmp->seq = htons(seq);
        break;
    default:
        return -1;
    }

    /* Fill with values */
    for ( i = sizeof(struct icmp_hdr); i < pktsize; i++ ) {
        buf[i] = i % 0xff;
    }
    icmp->checksum = checksum(buf, pktsize);

    *tm = microtime();
    ret = sendto(sock, buf, pktsize, 0, (struct sockaddr *)dai->ai_addr,
                 dai->ai_addrlen);
    if ( ret < 0 ) {
        /* Failed to send the packet */
        return -1;
    }

    return 0;
}

/*
 * Receive an ICMP echo reply
 */
static int
_ping_recv(struct slping *slp, int family)
{
    uint8_t buf[BUFFER_SIZE];
    struct sockaddr_storage saddr;
    socklen_t saddrlen;
    ssize_t nr;
    struct icmp_hdr *ricmp;
    struct ip_hdr *rip;
    int iphdrlen;
    struct ping_entry *e;
    double tm;
    uint16_t seq;
    uint16_t ident;

    /* Receive a packet */
    saddrlen = sizeof(saddr);
    switch ( family ) {
    case AF_INET:
        nr = recvfrom(slp->sock4, buf, BUFFER_SIZE, 0,
                      (struct sockaddr *)&saddr, &saddrlen);
        /* Check the length */
        if ( nr < 0 ) {
            /* Read nothing */
            return -1;
        }
        if ( nr < (ssize_t)sizeof(struct ip_hdr) ) {
            return -1;
        }
        tm = microtime();

        /* IP header */
        rip = (struct ip_hdr *)buf;
        iphdrlen = rip->verlen & 0xf;
        if ( nr < 4 * iphdrlen + (ssize_t)sizeof(struct icmp_hdr) ) {
            return -1;
        }
        /* Skip IP header */
        ricmp = (struct icmp_hdr *)(buf + 4 * iphdrlen);
        if ( ICMP_TYPE_ECHO_REPLY != ricmp->type || 0 != ricmp->code ) {
            /* Error */
            return -1;
        }
        seq = ntohs(ricmp->seq);
        ident = ntohs(ricmp->ident);

        break;
    case AF_INET6:
        nr = recvfrom(slp->sock6, buf, BUFFER_SIZE, 0,
                      (struct sockaddr *)&saddr, &saddrlen);
        /* Check the length */
        if ( nr < 0 ) {
            /* Read nothing */
            return -1;
        }
        if ( nr < (ssize_t)sizeof(struct icmp_hdr) ) {
            return -1;
        }
        tm = microtime();

        /* ICMPv6 */
        ricmp = (struct icmp_hdr *)buf;
        if ( ICMPV6_TYPE_ECHO_REPLY != ricmp->type || 0 != ricmp->code ) {
            /* Error */
            return -1;
        }
        seq = ntohs(ricmp->seq);
        ident = ntohs(ricmp->ident);

        break;
    default:
        return -1;
    }

    /* Search the corresponding */
    e = slp->head;
    while ( NULL != e ) {
        if ( e->family == saddr.ss_family
             && e->seq == seq && e->ident == ident ) {
            if ( saddr.ss_family == AF_INET ) {
                if ( e->u.in.sin_addr.s_addr
                     == ((struct sockaddr_in *)&saddr)->sin_addr.s_addr ) {
                    printf("%s %lf\n", e->target, tm - e->t0);
                    fflush(stdout);
                    break;
                }
            } else if ( saddr.ss_family == AF_INET6 ) {
                if ( memcmp(e->u.in6.sin6_addr.s6_addr,
                            ((struct sockaddr_in6 *)&saddr)->sin6_addr.s6_addr,
                            sizeof(e->u.in6.sin6_addr.s6_addr)) == 0 ) {
                    printf("%s %lf\n", e->target, tm - e->t0);
                    break;
                }
            } else {
                return -1;
            }
        }
        e = e->next;
    }
    if ( NULL != e ) {
        _remove_entry(slp, e);
    }

    return 0;
}

/*
 * Send a ping
 */
static int
_ping(struct ping_entry *ent, int family, int sock, int seq)
{
    struct addrinfo *ai;
    struct addrinfo hints;
    struct addrinfo *ressave;
    int err;
    double t0;
    uint16_t ident;
    double tm;

    /* Setup ai and hints to get address info */
    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_DGRAM;
    err = getaddrinfo(ent->target, NULL, &hints, &ressave);
    if ( 0 != err ) {
        /* Cannot resolve the target host */
        return -1;
    }
    /* Save the first addrinfo */
    if ( NULL == ressave ) {
        /* Error if the first addrinfo is NULL */
        freeaddrinfo(ressave);
        return -1;
    }
    ai = ressave;

    /* Allocate for the results */

    /* Obtain the started time */
    t0 = microtime();

    ident = random();
    err = _ping_send(family, sock, ai, ident, seq, 64, &tm);
    if ( 0 != err ) {
        freeaddrinfo(ressave);
        return -1;
    }

    /* Set the ping information */
    ent->ident = ident;
    ent->t0 = t0;
    ent->seq = seq;
    ent->family = family;
    if ( family == AF_INET ) {
        memcpy(&ent->u.in, ai->ai_addr, sizeof(struct sockaddr_in));
    } else if ( family == AF_INET6 ) {
        memcpy(&ent->u.in6, ai->ai_addr, sizeof(struct sockaddr_in6));
    }

    /* Free the returned addrinfo */
    freeaddrinfo(ressave);

    return 0;
}

/*
 * Read from the file descriptor
 */
int
_stdin_read(struct slping *slp, FILE *fp)
{
    char buf[BUFFER_SIZE];
    char *r;
    ssize_t len;
    struct ping_entry *ent;
    int ipv6;
    int i;

    if ( 0 != feof(fp) ) {
        return -1;
    }
    r = fgets(buf, BUFFER_SIZE, fp);
    if ( NULL == r ) {
        return -1;
    }
    len = strlen(buf);
    /* Trim */
    while ( len >= 0
            && ('\r' == buf[len] || '\n' == buf[len] || '\0' == buf[len]) ) {
        buf[len] = '\0';
        len--;
    }

    /* Allocate an entry */
    ent = malloc(sizeof(struct ping_entry));
    if ( NULL == ent ) {
        return -1;
    }
    ent->target = strdup(buf);
    if ( NULL == ent->target ) {
        free(ent);
        return -1;
    }
    ent->ident = 0;
    ent->t0 = 0;
    ent->next = NULL;

    if ( NULL == slp->tail ) {
        slp->head = ent;
        slp->tail = ent;
    } else {
        slp->tail->next = ent;
        slp->tail = ent;
    }

    /* Check if it's IPv4 or IPv6 */
    ipv6 = 0;
    for ( i = 0; i < (int)strlen(buf); i++ ){
        if ( ':' == buf[i] ) {
            ipv6 = 1;
            break;
        }
    }
    if ( ipv6 ) {
        _ping(ent, AF_INET6, slp->sock6, slp->curseq);
    } else {
        _ping(ent, AF_INET, slp->sock4, slp->curseq);
    }
    slp->curseq++;

    return 0;
}

/*
 * Main routine
 */
int
main(int argc, const char *const argv[])
{
    int sock4;
    int sock6;
    FILE *fin;
    FILE *fout;
    struct pollfd fds[3];
    int events;
    double gto;
    int ret;
    struct slping slp;

    /* Set up the input and output */
    fin = stdin;
    fout = stdout;

    /* Initialize slping structure */
    slp.head = NULL;
    slp.tail = NULL;
    slp.curseq = 1;

    /* Open IPv4 socket */
#if TARGET_FREEBSD || TARGET_NETBSD || TARGET_LINUX
    sock4 = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#else
    sock4 = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
#endif
    if ( sock4 < 0 ) {
        fprintf(stderr, "Cannot open IPv4 RAW socke.\n");
        return EXIT_FAILURE;
    }

    /* Open IPv6 socket */
#if TARGET_FREEBSD || TARGET_NETBSD || TARGET_LINUX
    sock6 = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
#else
    sock6 = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
#endif
    if ( sock6 < 0 ) {
        fprintf(stderr, "Cannot open IPv6 RAW socke.\n");
        return EXIT_FAILURE;
    }

    slp.sock4 = sock4;
    slp.sock6 = sock6;

    /* Set up the linked list */

    for ( ;; ) {
        /* Poll */
        fds[0].fd = fileno(fin);
        fds[0].events = POLLIN;
        fds[0].revents = 0;
        fds[1].fd = sock4;
        fds[1].events = POLLIN;
        fds[1].revents = 0;
        fds[2].fd = sock6;
        fds[2].events = POLLIN;
        fds[2].revents = 0;

        gto = 1.0;
        events = poll(fds, 3, (int)(gto * 1000));
        if ( events < 0 ) {
            if ( EINTR == errno ) {
                /* Interrupt */
                continue;
            } else {
                /* Other errors */
                return EXIT_FAILURE;
            }
        } else if ( 0 == events ) {
            /* Timeout */
            _gc(&slp);
            continue;
        } else {
            /* stdin */
            if ( fds[0].revents & (POLLERR | POLLHUP | POLLNVAL) ) {
                /* Error */
                fprintf(stderr, "Event error: stdin\n");
                return EXIT_FAILURE;
            } else if ( fds[0].revents & POLLIN ) {
                ret = _stdin_read(&slp, fin);
                if ( -1 == ret ) {
                    /* EOF read */
                    return EXIT_SUCCESS;
                }
            }
            /* IPv4 */
            if ( fds[1].revents & (POLLERR | POLLHUP | POLLNVAL) ) {
                /* Error */
                fprintf(stderr, "Event error: sock4\n");
                continue;
            } else if ( fds[1].revents & POLLIN ) {
                /* Received */
                ret = _ping_recv(&slp, AF_INET);
                if ( 0 != ret ) {
                    continue;
                }
                fflush(stdout);
            }
            /* IPv6 */
            if ( fds[2].revents & (POLLERR | POLLHUP | POLLNVAL) ) {
                /* Error */
                fprintf(stderr, "Event error: sock6\n");
                continue;
            } else if ( fds[2].revents & POLLIN ) {
                /* Received */
                ret = _ping_recv(&slp, AF_INET6);
                if ( 0 != ret ) {
                    continue;
                }
                fflush(stdout);
            }
        }
        /* GC */
        _gc(&slp);
    }

    return 0;
}

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: sw=4 ts=4 fdm=marker
 * vim<600: sw=4 ts=4
 */
