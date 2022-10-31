#include <iostream>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <queue>
#include <mutex>



int main()
{

    // C:\Users\user\Downloads\git-project-HOKM-server-crash-handing\pydbg_tests --> nop.exe

    PIMAGE_THUNK_DATA thunkData = {};
    DWORD thunk = NULL;
    DWORD rawOffset = NULL;
    HANDLE h_File = CreateFile(L"D:\\Cyber\\YB_CYBER\\project\\FinalProject\\ExeFiles\\Debug\\virus.exe", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (!h_File) {
        printf("\nERROR : Could not open the file specified\n");
    }

    //Mapping Given EXE file to Memory
    HANDLE hMapObject = CreateFileMapping(h_File, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID basepointer = (char*)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);

    //PIMAGE_DOS_HEADER dos_header;        
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)basepointer;
    printf("Magic number - %X\n", dos_header->e_magic);

    printf("DOS HEADER: IMAGE NT HEADER offset(Relative Address) - %X\n", dos_header->e_lfanew);  //DOS header working fine...

    //PIMAGE_NT_HEADERS ntHeader;         
    PIMAGE_NT_HEADERS nt_header = (PIMAGE_NT_HEADERS)((DWORD)basepointer + dos_header->e_lfanew);
    printf("NT HEADER: Signature %x\n", nt_header->Signature);

    PIMAGE_FILE_HEADER file_header = (PIMAGE_FILE_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature));
    printf("FILE HEADER: Machine %x\n", file_header->Machine);

    PIMAGE_OPTIONAL_HEADER optional_header = (PIMAGE_OPTIONAL_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader));
    printf("OPTIONAL HEADER: Image Base %x\n", optional_header->ImageBase);

    PIMAGE_SECTION_HEADER section_header = (PIMAGE_SECTION_HEADER)((DWORD)basepointer + dos_header->e_lfanew + sizeof(nt_header->Signature) + sizeof(nt_header->FileHeader) + sizeof(nt_header->OptionalHeader));
    DWORD numberofsections = file_header->NumberOfSections;
    printf("Section Header: Number of Sections %x\n", file_header->NumberOfSections);



    for (int j = 0; j < optional_header->NumberOfRvaAndSizes; j++) {
        printf("Data Directory: Virtual Address: %x\t\n", optional_header->DataDirectory[j].VirtualAddress);
    }

    DWORD RVAimport_directory = nt_header->OptionalHeader.DataDirectory[1].VirtualAddress;
    //printf("RVAimport_directory %x", RVAimport_directory);

    PIMAGE_SECTION_HEADER import_section = {};
    for (int i = 1; i <= numberofsections; i++, section_header++) {
        printf("Section Header: Section Name %s\n", section_header->Name);

        if (RVAimport_directory >= section_header->VirtualAddress && RVAimport_directory < section_header->VirtualAddress + section_header->Misc.VirtualSize) {

            import_section = section_header;
        }
        //section_header += (DWORD)sizeof(PIMAGE_SECTION_HEADER);
    }

    DWORD import_table_offset = (DWORD)basepointer + import_section->PointerToRawData;
    //imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress

    PIMAGE_IMPORT_DESCRIPTOR importImageDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(import_table_offset + (nt_header->OptionalHeader.DataDirectory[1].VirtualAddress - import_section->VirtualAddress));

    //DLL Imports
    //for (; importImageDescriptor->Name != 0; importImageDescriptor++) {
    //    DWORD Imported_DLL = import_table_offset + (importImageDescriptor->Name - import_section->VirtualAddress);
    //    printf("Imported DLLs: %s\n", Imported_DLL);
    //}

    printf("\n******* DLL IMPORTS *******\n");
    for (; importImageDescriptor->Name != 0; importImageDescriptor++) {

        // imported dll modules
        printf("\t%s\n", import_table_offset + (importImageDescriptor->Name - import_section->VirtualAddress));
        // printf("\t%d\n", import_table_offset + (importImageDescriptor->Name - import_section->VirtualAddress)); --> address
        thunk = importImageDescriptor->OriginalFirstThunk == 0 ? importImageDescriptor->FirstThunk : importImageDescriptor->OriginalFirstThunk;
        thunkData = (PIMAGE_THUNK_DATA)(import_table_offset + (thunk - import_section->VirtualAddress));

        // dll exported functions
        for (; thunkData->u1.AddressOfData != 0; thunkData++) {
            //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
            if (thunkData->u1.AddressOfData > 0x80000000) {
                //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                printf("\t\tOrdinal: %x\n", (WORD)thunkData->u1.AddressOfData);
            }
            else {
                printf("\t\t%s\n", (import_table_offset + (thunkData->u1.AddressOfData - import_section->VirtualAddress + 2)));
            }
        }
    }

}