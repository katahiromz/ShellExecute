// ShellExecute.cpp --- A test program for ShellExecute
// License: MIT
#include <windows.h>
#include <shlobj.h>
#include <psapi.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <stdio.h>

void version(void)
{
    std::printf("ShellExecute ver.1.0 by katahiromz\n");
}

void usage(void)
{
    std::printf(
        "ShellExecute --- A test program for ShellExecute by katahiromz.\n"
        "\n"
        "Usage: ShellExecute [OPTIONS] \"file\"\n"
        "       ShellExecute [OPTIONS] \"file\" [paramters]\n"
        "\n"
        "Options:\n"
        "  --operation OPERATION   Specify the operation (open, print, explorer etc.)\n"
        "  --help                  Display this message\n"
        "  --version               Display version info\n");
}

BOOL enableTokenPrivilege(LPCTSTR pszPrivilege)
{
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    TOKEN_PRIVILEGES tkp = { 0 };
    if (!LookupPrivilegeValue(NULL, pszPrivilege, &tkp.Privileges[0].Luid))
        return FALSE;

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    return AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
}

LPWSTR getCommandLineFromProcess(HANDLE hProcess)
{
    PEB peb;
    PROCESS_BASIC_INFORMATION info;
    RTL_USER_PROCESS_PARAMETERS Params;
    LONG status;
    BOOL ret;

    enableTokenPrivilege(SE_DEBUG_NAME);

    status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &info, sizeof(info), NULL);
    if (status != 0) // NOT STATUS_SUCCESS
    {
        std::printf("ERROR: NtQueryInformationProcess failed (status: 0x%08X)\n", status);
        return NULL;
    }

    ret = ReadProcessMemory(hProcess, info.PebBaseAddress, &peb, sizeof(peb), NULL);
    if (!ret)
    {
        std::printf("ERROR: ReadProcessMemory failed #1: (Error: 0x%08X)\n", GetLastError());
        return NULL;
    }

    ret = ReadProcessMemory(hProcess, peb.ProcessParameters, &Params, sizeof(Params), NULL);
    if (!ret)
    {
        std::printf("ERROR: ReadProcessMemory failed #2: (Error: 0x%08X)\n", GetLastError());
        return NULL;
    }

    LPWSTR pszCmdLine = Params.CommandLine.Buffer;
    SIZE_T cchCmdLine = Params.CommandLine.Length;
    LPWSTR pszBuffer = (LPWSTR)calloc(cchCmdLine + 1, sizeof(WCHAR));
    if (!pszBuffer)
    {
        std::printf("ERROR: Out of memory!\n");
        return NULL;
    }

    ret = ReadProcessMemory(hProcess, pszCmdLine, pszBuffer, cchCmdLine, NULL);
    if (!ret)
    {
        std::printf("ERROR: ReadProcessMemory failed #3: (Error: 0x%08X)\n", GetLastError());
        free(pszBuffer);
        return NULL;
    }

    pszBuffer[cchCmdLine] = 0;
    return pszBuffer; // needs free
}

enum RET
{
    RET_DONE = 0,
    RET_FAILED = -1,
    RET_SUCCESS = +1,
};

typedef std::vector<std::wstring> args_t;
std::wstring g_operation;

RET parse_cmd_line(args_t& args, INT argc, LPWSTR *argv)
{
    if (argc <= 1)
    {
        usage();
        return RET_DONE;
    }

    BOOL bNonOptionFound = FALSE;
    for (INT iarg = 1; iarg < argc; ++iarg)
    {
        std::wstring arg = argv[iarg];

        if (arg[0] == L'-' && !bNonOptionFound)
        {
            if (arg == L"--help")
            {
                usage();
                return RET_DONE;
            }

            if (arg == L"--version")
            {
                version();
                return RET_DONE;
            }

            if (arg == L"--operation")
            {
                if (iarg + 1 < argc)
                {
                    g_operation = argv[iarg + 1];
                    ++iarg;
                    continue;
                }
                else
                {
                    std::fprintf(stderr, "ERROR: --operation requires an argument\n");
                    return RET_FAILED;
                }
            }

            std::fprintf(stderr, "ERROR: Invalid option '%ls'\n", arg.c_str());
            return RET_FAILED;
        }

        bNonOptionFound = TRUE;
        args.push_back(arg);
    }

    if (args.empty())
    {
        std::fprintf(stderr, "ERROR: No arguments\n");
        return RET_FAILED;
    }

    return RET_SUCCESS;
}

INT _wmain(INT argc, LPWSTR *argv)
{
    args_t args;
    switch (parse_cmd_line(args, argc, argv))
    {
    case RET_DONE:
        return 0;
    case RET_FAILED:
        return -1;
    case RET_SUCCESS:
        break;
    }

    std::wstring strParams;
    for (size_t i = 1; i < args.size(); ++i)
    {
        if (i != 1)
            strParams += L' ';

        std::wstring arg = args[i];
        if (arg.find(' ') != arg.npos || arg.find('\t') != arg.npos)
        {
            strParams += L'"';
            strParams += arg;
            strParams += L'"';
        }
        else
        {
            strParams += arg;
        }
    }

    LPCWSTR operation = g_operation.size() ? g_operation.c_str() : NULL;
    LPCWSTR params = strParams.size() ? strParams.c_str() : NULL;

    SHELLEXECUTEINFOW info = { sizeof(info) };
    info.fMask =  SEE_MASK_NOCLOSEPROCESS;
    info.hwnd = NULL;
    info.lpVerb = operation;
    info.lpFile = args[0].c_str();
    info.lpParameters = params;
    info.nShow = SW_SHOWNORMAL;

    BOOL fOK = ShellExecuteExW(&info);
    if (fOK)
        std::printf("Success.\n");
    else
        std::printf("FAILED.\n");

    std::printf("ret: %d\n", (INT)(INT_PTR)info.hInstApp);

    if (info.hProcess)
    {
        LPWSTR pszCmdLine = getCommandLineFromProcess(info.hProcess);
        if (pszCmdLine)
        {
            printf("Command Line: %ls\n", pszCmdLine);
            free(pszCmdLine);
        }
        else
        {
            printf("WARNING: Couldn't get command line.\n");
        }
        CloseHandle(info.hProcess);
    }
    else
    {
        std::printf("No process info.\n");
    }

    g_operation = g_operation;
    strParams = strParams;
    return 0;
}

int main(void)
{
    int argc;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int ret = _wmain(argc, argv);
    LocalFree(argv);
    return ret;
}
