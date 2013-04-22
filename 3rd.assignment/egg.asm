; Egg - Assembly Language - Linux/x86
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


;   egg
;
;   # nasm -f elf32 egg.asm
;   # ld -m elf_i386 egg.o -o egg
;
;   Testing
;   # ./egg


global _start

section .text

_start:

	; egg signature (4 bytes * 2 = 8 bytes)

	nop
	push eax
	nop
	push eax

	; repeat signature

	nop
	push eax
	nop
	push eax


	; Write "Egg Mark"

	xor ebx, ebx
	mul ebx

	mov al, 4
	push 0xA
	push 0x6b72614d
	push 0x20676745
	mov bl, 1
	mov ecx, esp
	mov dl, 9
	int 0x80


	; Exit

	mov al, 1
	int 0x80
