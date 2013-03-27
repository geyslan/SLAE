; Egg - Assembly Language
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


; egg
;
;
; # nasm -f elf32 egg.asm
; # ld -m elf_i386 egg.o -o egg
;
; Testing
; # ./egg


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
