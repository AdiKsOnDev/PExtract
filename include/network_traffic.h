#ifndef PCAP_ANALYZER
#define PCAP_ANALYZER

#include <windows.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>

// Function pointer types for hooking
typedef int (WSAAPI *LPFN_CONNECT)(SOCKET, const struct sockaddr*, int);
LPFN_CONNECT oldConnect;

/* Function to start a child process 
 * Used to run the PE file in order to track 
 * its network traffic
 * -------------------------------------------
 * param: pe_path, Path string to the executable file  
 * 
 * return: void
 */
void start_child_process(char* pe_path);

/* A function to inject a DLL file into a
 * running process
 *
 * param: pid, Process ID
 * param: dll_path, path string to the executable file 
 *
 * return: boolean
 */
BOOL inject_dll(DWORD pid, char* dll_path)

int WSAAPI HookedConnect(SOCKET s, const struct sockaddr *name, int namelen);

/* Function to capture packets related to the process
 * -------------------------------------------
 * param: param,
 * param: header, Packet header
 * param: pkt_data, Data from the packet
 *
 * return: void
 */ 
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data); 

/* Function that combines all the previously defined
 * ones in order to capture PE file's network
 * traffic 
 * -------------------------------------------
 * param: pe_path, Path string to the PE file
 * param: dll_path, Path string to the DLL file
 *
 * return: void
 */
void capture_network_traffic(char* pe_path, char* dll_path);

#endif // !PCAP_ANALYZER
