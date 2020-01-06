// wizard
//
// Copyright (c) 2016, 2020 Joe Glancy
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#define _XOPEN_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// constants:

#define PROGRAM_NAME                        "wizard"
#define PROGRAM_VERSION_STR                 "0.1.0"

#define INADDR_SEND                         INADDR_LOOPBACK

#define NL_BUFLEN                           8192

// enums:

enum {
    GIP4_VAL = 0x47495034, // "GIP4" (get IPv4 address)
    RIP4_VAL = 0x54495034  // "RIP4" (returned IPv4 address)
};

typedef enum {
    C_RST = 0,
    C_RED = 1,
    C_GRN = 2,
    C_YLW = 3
} color_t;

typedef enum {
    COLOR_MODE_AUTO,
    COLOR_MODE_ALWAYS,
    COLOR_MODE_NEVER
} color_mode_t;

// colored output related stuff:

static const char *const color_table_color[] = {
    "\033[0m",
    "\033[1;31m",
    "\033[1;32m",
    "\033[1;33m"
};
static const char *const color_table_nocolor[] = {
    "",
    "",
    "",
    ""
};

static char *appname                        = nullptr;

#define C(n) config->color_output ? color_table_color[n] : color_table_nocolor[n]

// output/debugging macros:

#define info(a, b...)  if (config->verbose) fprintf(stderr, "%sinfo%s[%u][%s:%u]: " a, C(C_GRN), C(C_RST), (unsigned) getpid(), __FUNCTION__, __LINE__, ##b)
#define error(a, b...) if (!config->quiet)  fprintf(stderr, "%serror%s[%u][%s:%u]: " a, C(C_RED), C(C_RST), (unsigned) getpid(), __FUNCTION__, __LINE__, ##b)
#define perror(func)   error(func "(): %s", strerror(errno))

// classes/structures

struct config
{
    config():
        server_ip_str(nullptr),
        server_port(26255),
        broadcast_delay(10),
        get_ip_retries(-1),

        color_mode(COLOR_MODE_AUTO),

        server(0),
        verbose(0),
        quiet(0)
        { }

    char    *server_ip_str;
    uint16_t server_port;
    unsigned broadcast_delay;
    int      get_ip_retries;

    color_mode_t color_mode;

    uint64_t server:1;
    uint64_t verbose:1;
    uint64_t quiet:1;
    uint64_t color_output:1;
    uint64_t:0;
};

enum {
    ROUTE_FLAG_SRC = 0x00000001,
    ROUTE_FLAG_DST = 0x00000002,
    ROUTE_FLAG_GW  = 0x00000004,
    ROUTE_FLAG_IF  = 0x00000008
};

struct route
{
    route():
        family(0),
        iface(-1),
        flags(0)
        { }

    int family;
    int iface;
    uint32_t flags;
};

struct route_ipv4: route
{
    route_ipv4()
    {
        memset((void*) this, 0, sizeof(*this));
        family = AF_INET;
    }

    uint32_t src;
    uint32_t dst;
    uint32_t gateway;
    uint32_t mask;
};

struct netlink_msg
{
    netlink_msg() {
        memset((void*) this, 0, sizeof(*this));
    }

    struct nlmsghdr nlm;
    struct rtmsg rtm;
    char attrbuf[1024];
} __attribute__((packed));

// utility functions

// function wrapping strtol
int
strtol(struct config *config,
       char *s,
       long *dest,
       int base=0)
{
    long l;
    char *endptr;
    errno = 0;
    l = strtol((const char*) s, &endptr, base);
    if (errno != 0) {
        perror("strtol");
        return -1;
    } else if (endptr == nullptr) {
        error("'%s' does not contain any digits\n", s);
        return -1;
    } else if (*endptr != '\0') {
        error("unexpected non-numerical characters after digits: '%s'\n", endptr);
        return -1;
    }
    *dest = l;
    return 0;
}

static inline size_t
get_page_size(void)
{
    long l = sysconf(_SC_PAGESIZE);
    return l <= 0 ? 4096 : (size_t) l;
}

// utility function to get the IP for a local interface

static int
get_local_ip(struct config *config,
             struct route *dest)
{
    int sock = -1;
    size_t pagesize = get_page_size(), bufsize = pagesize, replysize = 0, rtlen;
    ssize_t nbytes;
    struct netlink_msg request_msg;
    struct rtmsg *rtm;
    struct rtattr *rta;
    struct nlmsghdr *nlm;
    void *buf, *newbuf;
    uint32_t curtime = (uint32_t) (time(nullptr) % UINT_MAX);

    buf = malloc(bufsize);
    if (buf == nullptr) {
        perror("malloc");
        goto err;
    }

    sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        goto err;
    }

    request_msg.nlm.nlmsg_len   = NLMSG_LENGTH(sizeof(struct rtmsg));
    request_msg.nlm.nlmsg_type  = RTM_GETROUTE;
    request_msg.nlm.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request_msg.nlm.nlmsg_seq   = curtime;
    request_msg.rtm.rtm_family  = dest->family;
    request_msg.rtm.rtm_table   = RT_TABLE_MAIN;

    nbytes = send(sock, (void*) &request_msg, sizeof(request_msg), 0);
    if (nbytes < 0) {
        perror("send");
        goto err;
    }

    for (;;) {
        nbytes = recv(sock, (void*) ((uint8_t*) buf + replysize), bufsize - replysize, 0);
        if (nbytes < 0) {
            perror("recv");
            goto err;
        } else if (nbytes == 0) {
            error("read 0 bytes while attempting to read NetLink response\n");
            goto err;
        }

        nlm = (struct nlmsghdr*) ((uint8_t*) buf + replysize);

        if (nlm->nlmsg_type == NLMSG_DONE) {
            // received all the data
            break;
        } else if (nlm->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr*) NLMSG_DATA(nlm);
            error("NetLink error occurred, code: %d\n", err->error);
            goto err;
        }

        if (!(nlm->nlmsg_flags & NLM_F_MULTI)) {
            // not a multipart message - but it should be?
            error("received a non-multipart NetLink message before a NLMSG_DONE message\n");
            goto err;
        }

        replysize += nbytes;
        if (bufsize - replysize < pagesize) {
            // reallocate a larger buffer to make sure we have room for the next
            // read.
            bufsize += pagesize;
            newbuf = realloc(buf, bufsize);
            if (newbuf == nullptr) {
                perror("realloc");
                goto err;
            }
            buf = newbuf;
        }
    }

    close(sock);
    sock = -1;

    for (nlm = (struct nlmsghdr*) buf; NLMSG_OK(nlm, replysize); NLMSG_NEXT(nlm, replysize)) {
        if (nlm->nlmsg_type != RTM_NEWROUTE ||
            nlm->nlmsg_seq != curtime) {
            continue;
        }
        rtm = (struct rtmsg*) NLMSG_DATA(nlm);
        if (rtm->rtm_table != RT_TABLE_MAIN) {
            continue;
        }
        rtlen = (size_t) RTM_PAYLOAD(nlm);
        switch(dest->family) {
        // process each family properly
        case AF_INET: {
            struct route_ipv4 route;
            for (rta = (struct rtattr*) RTM_RTA(rtm); RTA_OK(rta, rtlen); rta = RTA_NEXT(rta, rtlen)) {
                switch (rta->rta_type) {
                case RTA_PREFSRC:
                    // source address
                    route.src = *((uint32_t*) RTA_DATA(rta));
                    route.flags |= ROUTE_FLAG_SRC;
                    break;
                case RTA_DST:
                    // destination address
                    route.dst = (int64_t) *((uint32_t*) RTA_DATA(rta));
                    route.flags |= ROUTE_FLAG_DST;
                    // generate the mask. TODO: is this correct?
                    route.mask = 0xffffffff << (32 - rtm->rtm_dst_len);
                    break;
                case RTA_GATEWAY:
                    // gateway address
                    route.gateway = *((uint32_t*) RTA_DATA(rta));
                    route.flags |= ROUTE_FLAG_GW;
                    break;
                case RTA_OIF:
                    // network interface ID
                    route.iface = *((int*) RTA_DATA(rta));
                    route.flags |= ROUTE_FLAG_IF;
                    break;
                }
            }
            // ignore the ROUTE_FLAG_DST for now (TODO FIXME fix this?), so that
            // we can assume that if RTA_DST wasn't provided, the destination is
            // 0.0.0.0
            if (route.dst == 0 && (route.flags & ROUTE_FLAG_SRC)) {
                // found the correct route
                *((struct route_ipv4*) dest) = route;
                goto end;
            }
            break;
        }
        case AF_INET6: {
            // IPv6 is not supported yet
            break;
        }
        }
    }

err:
    if (sock >= 0) {
        close(sock);
    }

    if (buf != nullptr) {
        free(buf);
    }

    return -1;

end:
    free(buf);

    return 0;
}

// core functions

static int
get_ip_4(struct config *config,
         uint32_t *dest)
{
    int i, send_sock, recv_sock, one = 1, get_ip_retries = config->get_ip_retries;
    struct sockaddr_in send_addr =      {AF_INET, 0, {INADDR_SEND}},
                       recv_addr =      {AF_INET, 0, {INADDR_ANY}},
                       broadcast_addr = {AF_INET, htons(config->server_port), {INADDR_BROADCAST}},
                       incoming_data_addr;
    socklen_t recv_addr_len = sizeof(recv_addr),
        incoming_data_addr_len = sizeof(incoming_data_addr);
    fd_set rfds;
    struct timeval select_timeout;
    uint32_t send_payload[2]; // 1st byte = GIP4, 2nd byte = IP
    uint32_t recv_payload[2]; // 1st byte = RIP4, 2nd byte = port to send IP to
    ssize_t ss;

    if ((send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ||
        (recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        if (send_sock >= 0) {
            shutdown(send_sock, 2);
        }
        return -1;
    }

    setsockopt(send_sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    setsockopt(send_sock, SOL_SOCKET, SO_BROADCAST, (void*) &one, sizeof(one));
    setsockopt(recv_sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));

    if (connect(send_sock, (const struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
        perror("connect");
        goto err;
    }

    if (bind(recv_sock, (const struct sockaddr*) &recv_addr, sizeof(recv_addr)) < 0) {
        perror("bind");
        goto err;
    }

    // get the port we bound to
    if (getsockname(recv_sock, (struct sockaddr*) &recv_addr, &recv_addr_len) < 0) {
        perror("getsockname");
        goto err;
    }

    send_payload[0] = htonl(GIP4_VAL);
    send_payload[1] = htonl(recv_addr.sin_port);

    FD_ZERO(&rfds);
    FD_SET(recv_sock, &rfds);

    for (;;) {
        // broadcast the message
        info("broadcasting request\n");
        if ((ss = sendto(send_sock, (const void*) send_payload, 8, 0,
            (struct sockaddr*) &broadcast_addr, sizeof(broadcast_addr))) < 0) {
            error("sendto() call failed\n");
            perror("sendto");
            goto err;
        }
        // refill the select_timeout struct
        select_timeout.tv_sec = config->broadcast_delay;
        select_timeout.tv_usec = 0;
        // await a response on recv_sock
        if ((i = select(recv_sock + 1, &rfds, nullptr, nullptr, &select_timeout)) < 0) {
            error("select() call failed\n");
            perror("select");
            goto err;
        } else if (i == 0) {
            // no data, so re-broadcast if possible
            if (config->get_ip_retries > -1) {
                get_ip_retries -= 1;
                if (get_ip_retries <= 0) {
                    // no response after n broadcasts, so fail
                    info("no response after %d attempt%s, failing\n", config->get_ip_retries + 1,
                        config->get_ip_retries == 1 ? "" : "s");
                    goto err;
                }
            }
            info("no response, re-broadcasting . . .\n");
            continue;
        }

        // data available, assume response from server
        incoming_data_addr_len = sizeof(incoming_data_addr);
        if ((ss = recvfrom(recv_sock, (void*) recv_payload, 8, 0,
            (struct sockaddr*) &incoming_data_addr, &incoming_data_addr_len)) < 0) {
            error("recvfrom() call failed\n");
            perror("recvfrom");
            goto err;
        }

        recv_payload[0] = ntohl(recv_payload[0]);
        if (recv_payload[0] != RIP4_VAL) {
            // invalid magic value, drop it
            error("invalid magic value from received packet: 0x%X (%c%c%c%c)\n", recv_payload[0],
                (char) ((recv_payload[0] >> 24) & 0xFF), (char) ((recv_payload[0] >> 16) & 0xFF),
                (char) ((recv_payload[0] >> 8) & 0xFF), (char) (recv_payload[0] & 0xFF));
            continue;
        }
        recv_payload[1] = ntohl(recv_payload[1]);
        break;
    }

    shutdown(send_sock, 2);
    shutdown(recv_sock, 2);

    *dest = recv_payload[1];

    return 0;

err:
    shutdown(send_sock, 2);
    shutdown(recv_sock, 2);
    return -1;
}

static int
serve_ip_4(struct config *config,
           uint32_t ip)
{
    int send_sock, recv_sock, one = 1;
    struct sockaddr_in send_addr =      {AF_INET, 0, {INADDR_SEND}},
                       recv_addr =      {AF_INET, htons(config->server_port), {INADDR_ANY}},
                       incoming_data_addr,
                       response_to_query_addr;
    socklen_t incoming_data_addr_len, response_to_query_addr_len;
    uint32_t send_payload[2]; // 1st byte = RIP4, 2nd byte = port to send IP to
    uint32_t recv_payload[2]; // 1st byte = GIP4, 2nd byte = IP
    ssize_t ss;

    if ((send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0 ||
        (recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("socket");
        if (send_sock >= 0) {
            shutdown(send_sock, 2);
        }
        return -1;
    }

    setsockopt(send_sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    setsockopt(recv_sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));

    if (connect(send_sock, (const struct sockaddr*) &send_addr, sizeof(send_addr)) < 0) {
        perror("connect");
        goto err;
    }

    if (bind(recv_sock, (const struct sockaddr*) &recv_addr, sizeof(recv_addr)) < 0) {
        perror("bind");
        goto err;
    }

    send_payload[0] = htonl(RIP4_VAL);
    send_payload[1] = htonl(ip);

    for (;;) {
        // await a query
        info("awaiting query . . .\n");
        incoming_data_addr_len = sizeof(incoming_data_addr);
        if ((ss = recvfrom(recv_sock, (void*) recv_payload, 8, 0,
            (struct sockaddr*) &incoming_data_addr, &incoming_data_addr_len)) < 0) {
            error("recvfrom() call failed\n");
            perror("recvfrom");
            goto err;
        }

        recv_payload[0] = ntohl(recv_payload[0]);
        if (recv_payload[0] != GIP4_VAL) {
            // invalid magic value, drop it
            error("invalid magic value from received packet: 0x%X (%c%c%c%c)\n", recv_payload[0],
                (char) ((recv_payload[0] >> 24) & 0xFF), (char) ((recv_payload[0] >> 16) & 0xFF),
                (char) ((recv_payload[0] >> 8) & 0xFF), (char) (recv_payload[0] & 0xFF));
            continue;
        }
        recv_payload[1] = ntohl(recv_payload[1]);
        if (recv_payload[1] > 65535 ||
            recv_payload[1] < 1) {
            // invalid port, so drop the query
            error("invalid port specified (%u), dropping query\n", recv_payload[1]);
            continue;
        }

        // send the response
        response_to_query_addr.sin_family = AF_INET;
        response_to_query_addr.sin_port = (uint16_t) recv_payload[1];
        response_to_query_addr.sin_addr.s_addr = incoming_data_addr.sin_addr.s_addr;
        response_to_query_addr_len = sizeof(response_to_query_addr);
        if ((ss = sendto(send_sock, (const void*) send_payload, 8, 0,
            (struct sockaddr*) &response_to_query_addr, response_to_query_addr_len)) < 0) {
            error("sendto() call failed.\n");
            perror("sendto");
            goto err;
        }
        info("sent reply to %s:%u\n", inet_ntoa(incoming_data_addr.sin_addr),
            recv_payload[1]);
    }

    shutdown(send_sock, 2);
    shutdown(recv_sock, 2);

    return 0;

err:
    shutdown(send_sock, 2);
    shutdown(recv_sock, 2);
    return -1;
}

static int
do_get_ip_4(struct config *config)
{
    uint32_t ip;
    if (get_ip_4(config, &ip) < 0) {
        // error
        return -1;
    }

    char strbuf[INET_ADDRSTRLEN + 1];

    if (inet_ntop(AF_INET, (const void*) &ip, strbuf, INET_ADDRSTRLEN + 1) == nullptr) {
        perror("inet_ntop");
        return -1;
    }

    strbuf[INET_ADDRSTRLEN] = '\0';
    fputs(strbuf, stdout);
    return 0;
}

static int
do_serve_ip_4(struct config *config)
{
    int i;
    uint32_t ip;
    // ip string specified?
    if (config->server_ip_str) {
        if ((i = inet_pton(AF_INET, (const char*) config->server_ip_str, (void*) &ip)) != 1) {
            if (i) {
                perror("inet_pton");
                return -1;
            } else {
                error("invalid network address: %s\n", config->server_ip_str);
                return -1;
            }
        }
    } else {
        struct route_ipv4 route;
        if (get_local_ip(config, (struct route*) &route) < 0) {
            error(
                "couldn't determine local IP address. Please specify one manually\n"
                "using the -a option.\n"
            );
            return -1;
        }
        ip = route.src;

        char strbuf[INET_ADDRSTRLEN + 1];
        if (inet_ntop(AF_INET, (const void*) &ip, strbuf, INET_ADDRSTRLEN + 1) == nullptr) {
            perror("inet_ntop");
            return -1;
        }
        strbuf[INET_ADDRSTRLEN] = '\0';

        info("note: using %s as the server IP address.\n", strbuf);
    }

    return serve_ip_4(config, ip);
}

// main functions

#define usage_short(retcode) usage(retcode, false);

static void __attribute__((noreturn))
usage(int retcode, bool full=true)
{
    fprintf(stderr,
        "usage: %s [-h] [-v] [-q] [-V] [-c <mode>] [-s] [-a <ip>] [-p <port>]\n"
        "          [-d <delay>] [-n <attempts>]\n",
        appname
    );
    if (full)
    fprintf(stderr,
        "Options:\n"
        " -h            Display this help message.\n"
        " -v            Display the program's version.\n"
        " -q            Quiet program operation (suppress all error output).\n"
        " -V            Verbose program operation (output extra information).\n"
        " -c <mode>     Specify the color output mode to use. <mode> should be one\n"
        "               of:\n"
        "                 auto          (default)\n"
        "                 always\n"
        "                 never\n"
        " -s            Listen for broadcasts from clients, and respond (server\n"
        "               mode).\n"
        " -a <ip>       Specify the server IP when used in conjunction with the -b\n"
        "               option. If this option is not supplied, the local machine's\n"
        "               IP is used as the server IP.\n"
        " -p <port>     Specify the broadcast port. This should match on both the\n"
        "               server and the client(s).\n"
        " -d <delay>    Specify the delay (in seconds) between each re-broadcast in\n"
        "               client mode if there was no reponse from a server. Must be\n"
        "               1 or above (default: 10 seconds).\n"
        " -n <attempts> Specify the maximum retries to attempt in client mode if a\n"
        "               response is not obtained from a server. Must be 0 or above,\n"
        "               however a value of -1 specifies unlimited retries (the\n"
        "               default).\n"
        "\n"
        "The informational and error message format is as follows:\n"
        "    status[PID][function:line]\n"
        "Where <status> is either 'info' or 'error', <PID> is the ID of the process,\n"
        "and <function>/<line> are the name of the function and line at which the\n"
        "message was raised from, respectively.\n"
    );
    exit(retcode);
}

static void __attribute__((noreturn))
version(void)
{
    fprintf(stderr, PROGRAM_NAME " v" PROGRAM_VERSION_STR);
    exit(0);
}

extern "C" int
main(int argc,
     char **argv)
{
    appname = argv[0];


    struct config _config, *config = &_config;
    int c, ret;

    while ((c = getopt(argc, argv, "hvqVc:sa:p:d:n:")) != -1) {
        switch(c) {
        case 'h': // display help
            usage(0);
        case 'v': // display version
            version();
        case 'q': // quiet operation
            config->quiet = 1;
            break;
        case 'V': // verbose operation
            config->verbose = 1;
            break;
        case 'c': { // color output mode
            if (!strcmp((const char*) optarg, "auto")) {
                config->color_mode = COLOR_MODE_AUTO;
            } else if (!strcmp((const char*) optarg, "always")) {
                config->color_mode = COLOR_MODE_ALWAYS;
            } else if (!strcmp((const char*) optarg, "never")) {
                config->color_mode = COLOR_MODE_NEVER;
            } else {
                error(
                    "-c: invalid color mode: '%s'.\n"
                    "Only 'auto', 'always' and 'never' are valid color modes.\n",
                    optarg
                );
                usage_short(1);
            }
        }
            break;
        case 's': // act in server mode instead of client mode
            config->server = true;
            break;
        case 'a': // server address
            config->server_ip_str = optarg;
            break;
        case 'p': { // broadcast port
            long l;
            if (strtol(config, optarg, &l) < 0) {
                usage_short(1);
            }
            if (l < 1 || l > 65535) {
                error("port must be within 1 and 65535 (got %s)\n", optarg);
                usage_short(1);
            }
            config->server_port = (uint16_t) l;
        }
            break;
        case 'd': { // delay between broadcasts
            long l;
            if (strtol(config, optarg, &l) < 0) {
                usage_short(1);
            }
            if (l <= 0 || l > UINT_MAX) {
                error("delay between broadcasts must greater than 0 and smaller than %u (got %s)\n",
                    UINT_MAX, optarg);
                usage_short(1);
            }
            config->broadcast_delay = (unsigned) l;
        }
            break;
        case 'n': { // number of times to re-broadcast before failing
            long l;
            if (strtol(config, optarg, &l) < 0) {
                usage_short(1);
            }
            if ((l <= 0 || l > INT_MAX) && l != -1) {
                error(
                    "retry count must greater than 0 and smaller than %d (however -1 can also be\n"
                    "used to represent infinite retries until a response\n is acquired)\n"
                    "(got %s)\n",
                    INT_MAX, optarg);
                usage_short(1);
            }
            config->get_ip_retries = (int) l;
        }
            break;
        default:
            usage_short(1);
            break;
        }
    }

    // enable or disable color output appropriately
    switch(config->color_mode) {
    case COLOR_MODE_AUTO:
        config->color_output = isatty(STDIN_FILENO) ? 1 : 0;
        break;
    case COLOR_MODE_ALWAYS:
        config->color_output = 1;
        break;
    case COLOR_MODE_NEVER:
        config->color_output = 0;
        break;
    }

    if (config->server) {
        ret = do_serve_ip_4(config);
    } else {
        ret = do_get_ip_4(config);
    }

    return ret ? 1 : 0;
}
