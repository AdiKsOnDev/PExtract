#include "../include/network_traffic.h"

void start_child_process(char* pe_path) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    
    // Initialize with zeros
    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    SecureZeroMemory(&pi, sizeof(pi));
    
    // Start the child process.
    if (!CreateProcess(NULL,  // No module name (use command line)
        (LPSTR)pe_path,       // PE File
        NULL,                 // Process handle not inheritable
        NULL,                 // Thread handle not inheritable
        FALSE,                // Set handle inheritance to FALSE
        0,                    // No creation flags
        NULL,                 // Use parent's environment block
        NULL,                 // Use parent's starting directory 
        &si,                  // Pointer to STARTUPINFO structure
        &pi)                  // Pointer to PROCESS_INFORMATION structure
    ) {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return;
    }
    
    // Wait until child process exits.
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}
