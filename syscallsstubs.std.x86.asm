.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data

.code

EXTERN SW2_GetSyscallNumber: PROC

WhisperMain PROC
    pop eax                        ; Remove return address from CALL instruction
    call SW2_GetSyscallNumber      ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, fs:[0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword ptr fs:[0c0h]
    ret
WhisperMain ENDP

VegexOpenProcess PROC
    push 00A90331Fh
    call WhisperMain
VegexOpenProcess ENDP

VegexSuspendThread PROC
    push 0389FE53Eh
    call WhisperMain
VegexSuspendThread ENDP

VegexGetContextThread PROC
    push 018B44201h
    call WhisperMain
VegexGetContextThread ENDP

VegexSetContextThread PROC
    push 06AB0466Fh
    call WhisperMain
VegexSetContextThread ENDP

VegexResumeThread PROC
    push 09C47DAFDh
    call WhisperMain
VegexResumeThread ENDP

VegexAllocateVirtualMemory PROC
    push 0F6A8FC24h
    call WhisperMain
VegexAllocateVirtualMemory ENDP

VegexWriteVirtualMemory PROC
    push 0154209D9h
    call WhisperMain
VegexWriteVirtualMemory ENDP

VegexCreateThreadEx PROC
    push 024BCF6E6h
    call WhisperMain
VegexCreateThreadEx ENDP

VegexProtectVirtualMemory PROC
    push 0C95CFBE7h
    call WhisperMain
VegexProtectVirtualMemory ENDP

end