#include "../include/network_traffic.h"

void start_child_process(char *pe_path, char *dll_path) {
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  // Initialize with zeros
  SecureZeroMemory(&si, sizeof(si));
  si.cb = sizeof(si);
  SecureZeroMemory(&pi, sizeof(pi));

  // Start the child process.
  if (!CreateProcess(NULL,           // No module name (use command line)
                     (LPSTR)pe_path, // PE File
                     NULL,           // Process handle not inheritable
                     NULL,           // Thread handle not inheritable
                     FALSE,          // Set handle inheritance to FALSE
                     0,              // No creation flags
                     NULL,           // Use parent's environment block
                     NULL,           // Use parent's starting directory
                     &si,            // Pointer to STARTUPINFO structure
                     &pi)            // Pointer to PROCESS_INFORMATION structure
  ) {
    printf("CreateProcess failed (%d).\n", GetLastError());
    return;
  }

  if (!inject_dll(pi.dwProcessId, dll_path)) {
    printf("DLL injection failed.\n");
  }

  // Wait until child process exits.
  WaitForSingleObject(pi.hProcess, INFINITE);

  CloseHandle(pi.hProcess);
  CloseHandle(pi.hThread);
}

int WSAAPI HookedConnect(SOCKET s, const struct sockaddr *name, int namelen) {
    printf("Connect called\n");
    return oldConnect(s, name, namelen);
}

BOOL inject_dll(int pid, char *dll_path) {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (hProcess == NULL) {
    printf("OpenProcess failed (%d).\n", GetLastError());
    return FALSE;
  }

  LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dll_path) + 1,
                                   MEM_COMMIT, PAGE_READWRITE);
  WriteProcessMemory(hProcess, pDllPath, (LPVOID)dll_path, strlen(dll_path) + 1,
                     NULL);

  HANDLE hThread =
      CreateRemoteThread(hProcess, NULL, 0,
                         (LPTHREAD_START_ROUTINE)GetProcAddress(
                             GetModuleHandle("kernel32.dll"), "LoadLibraryA"),
                         pDllPath, 0, NULL);
  if (hThread == NULL) {
    printf("CreateRemoteThread failed (%d).\n", GetLastError());
    return FALSE;
  }

  WaitForSingleObject(hThread, INFINITE);
  VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
  CloseHandle(hThread);
  CloseHandle(hProcess);
  return TRUE;
}

void packet_handler(u_char *param, const struct pcap_pkthdr *header,
                    const u_char *pkt_data) {
  printf("Packet captured: %d bytes\n", header->len);
}

void capture_network_traffic(char *pe_path, char *dll_path) {
  start_child_process(pe_path, dll_path);

  // Packet capturing setup
  pcap_if_t *alldevs;
  pcap_if_t *d;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  int i = 0;

  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    printf("Error in pcap_findalldevs: %s\n", errbuf);
    return;
  }

  for (d = alldevs; d; d = d->next) {
    printf("%d. %s\n", ++i, (d->description) ? d->description : d->name);
  }

  if (i == 0) {
    printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
    return;
  }

  int devNum;
  printf("Enter the interface number (1-%d):", i);
  scanf("%d", &devNum);

  for (d = alldevs, i = 0; i < devNum - 1; d = d->next, i++)
    ;

  if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) {
    printf("Unable to open the adapter. %s is not supported by WinPcap\n",
           d->name);
    pcap_freealldevs(alldevs);
    return;
  }

  pcap_freealldevs(alldevs);

  pcap_loop(adhandle, 0, packet_handler, NULL);
  pcap_close(adhandle);
}
