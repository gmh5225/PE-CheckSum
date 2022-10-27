#include <Windows.h>

#include <stdio.h>

#include <Windows.h>
#include <ImageHlp.h>
#pragma comment(lib, "ImageHlp.lib")

unsigned long
LoadPEFile(const char *FileName, char **Buffer)
{
    FILE *fp = fopen(FileName, "rb");
    fseek(fp, 0, SEEK_END);
    unsigned long len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    *Buffer = new char[len + 4];
    memset(*Buffer, 0x0, len + 4);
    unsigned long i = 0;
    while (i < len)
    {
        fread(*Buffer + i, 4, 1, fp);
        i += 4;
    }
    fclose(fp);
    return len;
}

static WORD
CalcCheckSum(DWORD StartValue, LPVOID BaseAddress, DWORD WordCount)
{
    LPWORD p = (LPWORD)BaseAddress;
    DWORD sum = StartValue;
    for (DWORD i = 0; i < WordCount; i++)
    {
        sum += *p;
        if (((sum >> 16) & 0xffff) != 0)
        {
            sum = (sum & 0xffff) + ((sum >> 16) & 0xffff);
        }
        p++;
    }

    return (WORD)((sum & 0xffff) + ((sum >> 16) & 0xffff));
}

PIMAGE_NT_HEADERS WINAPI
MyCheckSumMappedFile(LPVOID BaseAddress, DWORD FileLength, LPDWORD HeaderSum, LPDWORD CheckSum)
{
    PIMAGE_NT_HEADERS header;
    DWORD CalcSum;
    DWORD HdrSum;

    CalcSum = CalcCheckSum(0, BaseAddress, (FileLength + 1) / sizeof(WORD));

    PIMAGE_DOS_HEADER DosHdr = (PIMAGE_DOS_HEADER)BaseAddress;
    PIMAGE_NT_HEADERS NtHdr = (PIMAGE_NT_HEADERS)((ULONG_PTR)BaseAddress + DosHdr->e_lfanew);

    header = NtHdr;

    if (!header)
        return NULL;

    *HeaderSum = HdrSum = header->OptionalHeader.CheckSum;

    if (LOWORD(CalcSum) >= LOWORD(HdrSum))
    {
        CalcSum -= LOWORD(HdrSum);
    }
    else
    {
        CalcSum = ((LOWORD(CalcSum) - LOWORD(HdrSum)) & 0xFFFF) - 1;
    }

    if (LOWORD(CalcSum) >= HIWORD(HdrSum))
    {
        CalcSum -= HIWORD(HdrSum);
    }
    else
    {
        CalcSum = ((LOWORD(CalcSum) - HIWORD(HdrSum)) & 0xFFFF) - 1;
    }

    CalcSum += FileLength;

    *CheckSum = CalcSum;

    return header;
}

int
main()
{
    DWORD headerCheckSum = 0;
    DWORD checkSum = 0;
    char *Buffer = NULL;
    unsigned long len = LoadPEFile("PE-CheckSum.exe", &Buffer);
    ::CheckSumMappedFile(Buffer, len, &headerCheckSum, &checkSum);
    printf("headerCheckSum=%p,checkSum=%p\n", headerCheckSum, checkSum);
    MyCheckSumMappedFile(Buffer, len, &headerCheckSum, &checkSum);
    printf("headerCheckSum=%p,checkSum=%p\n", headerCheckSum, checkSum);

    return 0;
}
