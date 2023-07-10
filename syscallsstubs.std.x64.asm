.data
currentHash DWORD 0

.code
EXTERN SW2_GetSyscallNumber: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        ; Issue syscall
    ret
WhisperMain ENDP

VegexOpenProcess PROC
    mov currentHash, 00A90331Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexOpenProcess ENDP

VegexSuspendThread PROC
    mov currentHash, 0389FE53Eh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexSuspendThread ENDP

VegexGetContextThread PROC
    mov currentHash, 018B44201h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexGetContextThread ENDP

VegexSetContextThread PROC
    mov currentHash, 06AB0466Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexSetContextThread ENDP

VegexResumeThread PROC
    mov currentHash, 09C47DAFDh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexResumeThread ENDP

VegexAllocateVirtualMemory PROC
    mov currentHash, 0F6A8FC24h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexAllocateVirtualMemory ENDP

VegexWriteVirtualMemory PROC
    mov currentHash, 0154209D9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexWriteVirtualMemory ENDP

VegexCreateThreadEx PROC
    mov currentHash, 024BCF6E6h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexCreateThreadEx ENDP

VegexProtectVirtualMemory PROC
    mov currentHash, 0C95CFBE7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
VegexProtectVirtualMemory ENDP

end