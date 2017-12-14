/*
    ssh-multipath-proxy
    Copyright (C) 2006  Kasper Dupont

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2, or (at your option)
    any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    $Id: ssh-multipath-proxy.c,v 1.17 2009/02/15 10:05:28 kasperd Exp $
*/

/*
    The purpose of this program is to serve as proxy for an ssh
    client allowing you to use alternate IPs and port numbers to
    connect to the same host.

    It will even allow you to specify an optional secondary proxy
    to fall back on in case all specified hosts fail.

    Configuration:
    For each host where you want to use this proxy add a
    ProxyCommand in your ~/.ssh/config, the command to be used
    is ssh-multipath-proxy followed by a number of hosts and
    optionally ends with "-- command" where command is an
    alternate proxy to use if all specified hosts fail. You can
    end the hostname with :portnumber to use a nonstandard port,
    if none is specified 22 will be used.


    If you want to be able to ssh from your laptop to your
    workstation, but only sometimes are on the same network and
    at other times need to use a portforwarding listening on port
    4242 on localhost, you would specify this:

    Host workstation
    ProxyCommand ssh-multipath-proxy localhost:4242 %h:%p

    In this example ssh will substitute %h and %p with hostname
    and port number before calling ssh-multipath-proxy.

    If you want to be able to ssh to a multi homed server with
    two names mapping to different IPs and have an alternate
    proxy tunneling your connection over something other than TCP
    you would specify this:

    Host server
    ProxyCommand ssh-multipath-proxy servername1 servername2 -- alternate-proxy

    Here port 22 will be used in both attempts. If any port
    number was specified in ~/.ssh/config it would be ignored
    since there is no %p in the ProxyCommand


    Features I'd like to add in the future:
    - Support hostnames resolving to multiple IPs.
    - Configurable timeouts.
    - IPv6 support.
    - Configurable use of setsid() (startup/connected/never)
    - Asynchronous DNS lookups
    - TCP Keep Alive

 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <ctype.h>
#include <assert.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>

struct socket_info {
  int fd;
  char *name;
  struct sockaddr_in sock_addr;
};

int select_loop(int fd)
{
  int src[2]={0,fd};
  int dst[2]={fd,1};
  char buffer[2][8192];
  int bufusage[2]={0,0};
  int active[2]={1,1};

  while(1) {
    int i;
    int max_fd=-1;
    fd_set rfd;
    fd_set wfd;
    FD_ZERO(&rfd);
    FD_ZERO(&wfd);
    for (i=0;i<2;++i) {
      if (bufusage[i]>0) {
        FD_SET(dst[i],&wfd);
        if (dst[i]>max_fd) max_fd=dst[i];
      }
      if (active[i]&&(bufusage[i]<4096)) {
        FD_SET(src[i],&rfd);
        if (src[i]>max_fd) max_fd=src[i];
      }
    }
    if (max_fd == -1) return 0;
    if (select(max_fd+1,&rfd,&wfd,NULL,NULL)<1) return -1;
    for (i=0;i<2;++i) {
      if ((bufusage[i]>0)&&(FD_ISSET(dst[i],&wfd))) {
        int towrite=bufusage[i];
        int r;
        if (towrite>4096) towrite=4096;
        r=write(dst[i],buffer[i],towrite);
        if (r<1) {
          active[i]=0;
          bufusage[i]=0;
        } else {
          bufusage[i]-=r;
          memcpy(buffer[i],buffer[i]+r,bufusage[i]);
        }
      }
      if (active[i]&&(bufusage[i]<4096)&&(FD_ISSET(src[i],&rfd))) {
        int r=read(src[i],buffer[i]+bufusage[i],4096);
        if (r<1) {
          active[i]=0;
        } else {
          bufusage[i]+=r;
        }
      }
      if ((!active[i])&&(bufusage[i]==0)&&(dst[i]>-1)) {
        shutdown(dst[i],SHUT_WR);
        if (i == 1) close(1);
        dst[i]=-1;
      }
    }
  }
}

/* This function will resolve the host name synchronously, and if that
 * succeeds try to open a TCP connection to the host. The TCP connection
 * is done asynchronously, and is checked in wait_for_reply.
 */
void try_to_connect(struct socket_info *s)
{
  int fd;
  uint16_t port=22;
  char *p;
  char *hostname=malloc(strlen(s->name)+1);
  struct hostent *host_addr;
  struct sockaddr_in sock_addr;

  s->fd=-1;

  if (!hostname) {
    perror("malloc");
    return;
  }
  strcpy(hostname,s->name);

  p=strrchr(hostname,':');
  if (p) {
    port=atoi(p+1);
    *p=0;
  }

  /* TODO: Support multiple IPs per hostname */
  host_addr=gethostbyname(hostname);
  if (!host_addr) {
    fprintf(stderr,"%s: no such host\n",hostname);
    return;
  }

  sock_addr.sin_family = AF_INET;
  sock_addr.sin_port = htons(port);
  sock_addr.sin_addr.s_addr= *(unsigned long int*)(host_addr->h_addr);

  fd=socket(PF_INET,SOCK_STREAM,0);
  if (fd==-1) {
    perror("socket");
    return;
  }
  fcntl(fd,F_SETFL,O_NONBLOCK);
  fcntl(fd,F_SETFD,FD_CLOEXEC);
  connect(fd,(struct sockaddr*)&sock_addr,sizeof(sock_addr));
  s->sock_addr=sock_addr;
  s->fd = fd;
}

int read_SSH(int fd)
{
  int l;
  char reply[3];
  l=read(fd,&reply,3);
  if (l<1) return -1;
  if (memcmp(reply,"SSH",l)) return -1;
  write(1,reply,l);
  return 0;
}

static inline int64_t timeval_to_int64(struct timeval tv)
{
  return ((int64_t)tv.tv_sec)*((int64_t)1000000)+((int64_t)tv.tv_usec);
}

/* wait_for_reply will wait for the given timeout starting from the
 * specified timeout for an SSH banner from any of the open sockets.
 * If it gets a reply, it will close all other sockets and forward
 * bytes between stdio and that socket. In this case the function
 * never returns. Otherwise the function returns 0 on timeout or if
 * all sockets are closed. If anything else happens it will return 1
 * in which case the caller is expected to recompute the timeout and
 * call wait_for_reply again.
 */
int wait_for_reply(struct socket_info *sockets, int *nr_open_sockets_ptr,
		   struct timeval start_time, int64_t timeout)
{
  struct timeval current_time;
  fd_set socket_fd_set;
  int i,max_fd=0;
  struct timeval timeout_tv;

  if (!*nr_open_sockets_ptr) return 0;

  if (timeout) {
    gettimeofday(&current_time,NULL);
    timeout+=timeval_to_int64(start_time);
    timeout-=timeval_to_int64(current_time);
    if (timeout<1) timeout=1;
    timeout_tv.tv_sec=timeout/1000000;
    timeout_tv.tv_usec=timeout%1000000;
  }

  FD_ZERO(&socket_fd_set);
  for (i=0;i<*nr_open_sockets_ptr;++i) {
    int s=sockets[i].fd;
    FD_SET(s,&socket_fd_set);
    if (s>max_fd) max_fd=s;
  }
  switch(select(max_fd+1,&socket_fd_set,NULL,NULL,timeout?&timeout_tv:NULL)) {
  case -1:
    perror("This should not happen - select");
    return 0;
  case 0:
    /* timeout */
    return 0;
  default:
    /* Naiiiice */
    for (i=0;i<*nr_open_sockets_ptr;++i)
      if (FD_ISSET(sockets[i].fd,&socket_fd_set)) {
	/* Remove this socket from the array */
	struct socket_info info=sockets[i];
	sockets[i]=sockets[--*nr_open_sockets_ptr];

	if(read_SSH(info.fd)) {
	  /* Not good, I didn't get a reply starting with SSH as expected */
	  /* It is already removed from the array, just step back the index */
	  --i;
	  close(info.fd);
	} else {
	  /* This sokcet looks good - point of no return - we will use it */
	  char sock_str[INET_ADDRSTRLEN+1];
	  inet_ntop(AF_INET,&(info.sock_addr.sin_addr),
		    sock_str,sizeof(sock_str)-1);
	  fprintf(stderr,"Using: %s (%s:%d)\n",info.name,sock_str,
		  ntohs(info.sock_addr.sin_port));
	  for (i=0;i<*nr_open_sockets_ptr;++i) {
	    close(sockets[i].fd);
	  }
	  exit(select_loop(info.fd)?EXIT_FAILURE:EXIT_SUCCESS);
	}
      } /* for ... if FD_ISSET */
  } /* switch */
  return 1;
}

/* Timeout is one second if we tried a connect within the last second and
 * did not get a reply yet. Otherwise timeout is just one microsecond
 */
int compute_timeout(int open_sockets,
		    struct socket_info *sockets,
		    int last_connect_fd)
{
  int timeout=1,i;
  for (i=0;i<open_sockets;++i) {
    if (sockets[i].fd == last_connect_fd) {
      timeout=1000000;
    }
  }
  return timeout;
}

int main(int argc, char ** argv)
{
  int cmdidx;
  struct socket_info *sockets;
  int open_sockets=0;
  int sockidx;

  int last_connect_fd=0;
  struct timeval last_connect_time;

  if (argc < 3) {
    fprintf(stderr,"Usage: %s <host1>[:port] <host2>[:port] [...] [-- command]\n",argv[0]);
    exit(EXIT_FAILURE);
  }

  for (cmdidx=1;(cmdidx<argc)&&strcmp(argv[cmdidx],"--");++cmdidx);
  if (cmdidx==1) {
    fprintf(stderr,"%s: At least one host required even with command\n",argv[0]);
    exit(EXIT_FAILURE);
  }
  if (cmdidx==argc-1) {
    fprintf(stderr,"%s: Command must not be empty\n",argv[0]);
    exit(EXIT_FAILURE);
  }

  sockets=malloc(sizeof(struct socket_info)*cmdidx);
  if (!sockets) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  if (setsid()==-1) perror("setsid()");

  for(sockidx=1;sockidx<cmdidx;++sockidx) {
    while(wait_for_reply(sockets,&open_sockets,last_connect_time,compute_timeout(open_sockets, sockets, last_connect_fd)));

    //fprintf(stderr,"Trying: %s\n",argv[sockidx]);
    sockets[open_sockets].name=argv[sockidx];
    try_to_connect(sockets+open_sockets);
    if (sockets[open_sockets].fd!=-1) {
      gettimeofday(&last_connect_time,NULL);
      last_connect_fd=sockets[open_sockets].fd;
      ++open_sockets;
    }
  }

  if(cmdidx<argc) {
    int i;
    /* Wait for up to three seconds before executing a command. */
    while(wait_for_reply(sockets,&open_sockets,last_connect_time,3000000));
    fprintf(stderr,"Running:");
    for (i=cmdidx+1;argv[i];++i)
      fprintf(stderr," %s",argv[i]);
    fprintf(stderr,"\n");
    execvp(argv[cmdidx+1],argv+cmdidx+1);
    perror(argv[cmdidx+1]);
    /* If the command failed we go back to wait on the sockets. */
  }

  /* No more hostnames to try, and no alternative command was found.
   * Wait indefinitely for a reply on one of the sockets.
   */
  while(wait_for_reply(sockets,&open_sockets,last_connect_time,0));

  /* All means of connecting have failed. Return an error. */
  return EXIT_FAILURE;
}
