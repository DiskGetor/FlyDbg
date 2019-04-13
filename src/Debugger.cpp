#include "pch.h"
#include "Debugger.h"

#include <iostream>

namespace fly {
    Debugger::Debugger() {
        // Init disasm decoder
#ifdef FLY_X86
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_ADDRESS_WIDTH_32);
#endif // FLY_X86

#ifdef FLY_X64
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
#endif // FLY_X64

        ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
        bContinueDebugging = true;
        initStatus = FLY_PENDING;
        debugEvent = { 0 };
        redirectStdoutToNull = false;
    }

    Debugger::~Debugger() {
        StopDebug();
    }

    // Private methods
    void Debugger::EnterDebugLoop() {
        const LPDEBUG_EVENT DebugEvent = &debugEvent;
        FlyUL dwContinueStatus = DBG_CONTINUE;
        int firstChanceCount = 0;
        FlyUI64 bpAddress = 0;

        while (bContinueDebugging.load()) {
            if (!WaitForDebugEvent(DebugEvent, INFINITE)) {                
                return;
            }

            switch (DebugEvent->dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT:
                switch (DebugEvent->u.Exception.ExceptionRecord.ExceptionCode) {
                case EXCEPTION_ACCESS_VIOLATION:
                    std::cout << "OutDbgMsg: [EXCEPTION_ACCESS_VIOLATION]" << std::endl;
                    break;

                case EXCEPTION_BREAKPOINT:
                    bpAddress = ((FlyUI64)(DebugEvent->u.Exception.ExceptionRecord.ExceptionAddress));
                    if (IsBpxEnabled(bpAddress)) {
                        TriggerBpxCallback(bpAddress);
                        dwContinueStatus = DBG_EXCEPTION_HANDLED;
                        break;
                    }

                    std::cout << "OutDbgMsg: [EXCEPTION_BREAKPOINT]" << std::endl;
                    dwContinueStatus = DBG_EXCEPTION_NOT_HANDLED;
                    break;

                case EXCEPTION_DATATYPE_MISALIGNMENT:
                    std::cout << "OutDbgMsg: [EXCEPTION_DATATYPE_MISALIGNMENT]" << std::endl;
                    break;

                case EXCEPTION_SINGLE_STEP:
                    std::cout << "OutDbgMsg: [EXCEPTION_SINGLE_STEP]" << std::endl;
                    break;

                case DBG_CONTROL_C:
                    std::cout << "OutDbgMsg: [DBG_CONTROL_C]" << std::endl;
                    break;

                default:
                    break;
                }

                break;

            case CREATE_THREAD_DEBUG_EVENT:
                std::cout << "OutDbgMsg: [CREATE_THREAD_DEBUG_EVENT]" << std::endl;
                break;

            case CREATE_PROCESS_DEBUG_EVENT:
                std::cout << "OutDbgMsg: [CREATE_PROCESS_DEBUG_EVENT]" << std::endl;
                break;

            case EXIT_THREAD_DEBUG_EVENT:
                std::cout << "OutDbgMsg: [EXIT_THREAD_DEBUG_EVENT]" << std::endl;
                break;

            case EXIT_PROCESS_DEBUG_EVENT:
                std::cout << "OutDbgMsg: [EXIT_PROCESS_DEBUG_EVENT]" << std::endl;
                bContinueDebugging = false;
                break;

            case LOAD_DLL_DEBUG_EVENT:
                std::cout << "OutDbgMsg: [LOAD_DLL_DEBUG_EVENT]" << std::endl;
                break;

            case UNLOAD_DLL_DEBUG_EVENT:
                std::cout << "OutDbgMsg: [UNLOAD_DLL_DEBUG_EVENT]" << std::endl;
                break;

            case OUTPUT_DEBUG_STRING_EVENT:
                std::cout << "OutDbgMsg: [OUTPUT_DEBUG_STRING_EVENT]" << std::endl;
                break;

            case RIP_EVENT:
                std::cout << "OutDbgMsg: [RIP_EVENT]" << std::endl;
                break;
            }

            ContinueDebugEvent(DebugEvent->dwProcessId,
                DebugEvent->dwThreadId,
                dwContinueStatus);
        }
    }

    // Debugger
    void Debugger::InitDebugThread(const std::wstring &inputFileName, const std::wstring &cmd, const std::wstring &currentPath) {
        memset(&procInfo, 0, sizeof(PROCESS_INFORMATION));
        memset(&startupInfo, 0, sizeof(STARTUPINFO));
        memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));

        startupInfo.cb = sizeof(startupInfo);
        startupInfo.dwFlags = STARTF_USESHOWWINDOW;
        startupInfo.wShowWindow = SW_SHOW;

        if (redirectStdoutToNull) {
            startupInfo.dwFlags |= STARTF_USESTDHANDLES;
            startupInfo.hStdInput = NULL;
            startupInfo.hStdError = NULL;
            startupInfo.hStdOutput = NULL;
        }

        LPCWSTR _exePath = inputFileName.c_str();
        std::wstring sargs = inputFileName + L" " + cmd;
        LPWSTR _args = (LPWSTR)(sargs.c_str());

        if (!::CreateProcess(_exePath, _args, NULL, NULL, false, CREATE_SUSPENDED | DEBUG_PROCESS, NULL, currentPath.c_str(), &startupInfo, &procInfo)) {
            initStatus = FLY_ERROR_CREATING_PROCESS;
            return;
        }

        mainThreadId = procInfo.dwThreadId;
        mainThreadHandle = ::OpenThread(THREAD_ALL_ACCESS, false, procInfo.dwThreadId);
        if (mainThreadHandle == INVALID_HANDLE_VALUE) {
            initStatus = FLY_ERROR_OPENING_MAIN_THREAD;
            return;
        }

        if (::NtQueryInformationProcess(procInfo.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0) {
            initStatus = FLY_ERROR_SEND_QUERY_INFORMATION;
            return;
        }

        if (FLY_IS_FAILED(ReadMemory((FlyUI64)pbi.PebBaseAddress, &peb, sizeof(PEB)))) {
            initStatus = FLY_ERROR_READING_PEB;
            return;
        }

        if (FLY_IS_FAILED(GetThreadContext(mainThreadHandle, ctx))) {
            initStatus = FLY_ERROR_READING_CONTEXT;
            return;
        }

        initStatus = FLY_SUCCESS;
        Debugger::EnterDebugLoop();
    }

    FlyStatus Debugger::InitDebug(const std::wstring &inputFileName, const std::wstring &cmd, const std::wstring &currentPath) {
        debugLoopThread = std::thread(&Debugger::InitDebugThread, this, inputFileName, cmd, currentPath);
        while (initStatus.load() == FLY_PENDING) { FLY_SLEEP(100); }
        return initStatus.load();
    }

    void Debugger::Run() {
        NtResumeProcess(procInfo.hProcess);
    }

    void Debugger::Pause() {
        NtSuspendProcess(procInfo.hProcess);
    }

    void Debugger::RedirectStdoutToNull() {
        redirectStdoutToNull = true;
    }

    FlyStatus Debugger::AttachToProcess(FlyUI64 processId) {
        if (initStatus.load() != FLY_PENDING) {
            return FLY_ALREADY_LOADED;
        }
        // TODO
        return FLY_SUCCESS;
    }
    
    FlyUI64 Debugger::GetImageBaseFromPEB() const {
        return (FlyUI64)peb.ImageBaseAddress;
    }

    FlyStatus Debugger::ReadMemory(FlyUI64 dwAddress, FlyVoidPtr buffer, size_t length) const {
        SIZE_T numberOfBytesRead;
        ::ReadProcessMemory(procInfo.hProcess, (LPCVOID)dwAddress, buffer, length, &numberOfBytesRead);
        return numberOfBytesRead == length ? FLY_SUCCESS : FLY_ERROR_READING_MEMORY;
    }

    FlyStatus Debugger::WriteMemory(FlyUI64 dwAddress, FlyVoidPtr buffer, size_t length) const {
        SIZE_T numberOfBytesWritten;
        ::WriteProcessMemory(procInfo.hProcess, (LPVOID)dwAddress, buffer, length, &numberOfBytesWritten);
        return numberOfBytesWritten == length ? FLY_SUCCESS : FLY_ERROR_WRITING_MEMORY;
    }

    FlyStatus Debugger::GetThreadContext(FlyVoidPtr hThread, CONTEXT &ctx) const {
        return ::GetThreadContext(hThread, &ctx) ? FLY_SUCCESS : FLY_ERROR_READING_CONTEXT;
    }

    FlyStatus Debugger::SetThreadContext(FlyVoidPtr hThread, const CONTEXT &ctx) const {
        return ::SetThreadContext(hThread, &ctx) ? FLY_SUCCESS : FLY_ERROR_WRITING_CONTEXT;
    }

    FlyStatus Debugger::StopDebug() {
        bContinueDebugging = false;
        if (procInfo.hProcess != INVALID_HANDLE_VALUE)
            ::TerminateProcess(procInfo.hProcess, 0);
        if (procInfo.hThread != INVALID_HANDLE_VALUE)
            ::CloseHandle(procInfo.hThread);
        if (procInfo.hProcess != INVALID_HANDLE_VALUE)
            ::CloseHandle(procInfo.hProcess);
        if (mainThreadHandle != INVALID_HANDLE_VALUE)
            ::CloseHandle(mainThreadHandle);
        if (debugLoopThread.joinable())
            debugLoopThread.join();

        return FLY_SUCCESS;
    }

    // Debugger.Tracer
    FlyStatus Debugger::SetBpx(FlyUI64 dwAddress, FlyBpxType bpxType, FlyBpxCallback &bpxCallback) {
        BPX bpx;
        DropBpx(dwAddress);
        bpx.bpxCallback = &bpxCallback;
        bpx.isEnabled = true;
        bpx.bxpType = bpxType;

        switch (bpxType) {
        case FLY_BP_INT3:
            bpx.size = 1;
            bpx.keepBytes = new char[bpx.size];

            FlyUL oldProtect;
            ::VirtualProtectEx(procInfo.hProcess, (LPVOID)dwAddress, bpx.size, PAGE_EXECUTE_READWRITE, &oldProtect);
            ReadMemory(dwAddress, bpx.keepBytes, bpx.size);            
            WriteMemory(dwAddress, (void*)INT3BreakPoint, bpx.size);
            ::VirtualProtectEx(procInfo.hProcess, (LPVOID)dwAddress, bpx.size, oldProtect, &oldProtect);
            break;
        default:
            return FLY_UNKNOWN_BREAKPOINT_TYPE;
        }

        bpxObj.insert({ dwAddress, bpx });
        return FLY_SUCCESS;
    }

    FlyStatus Debugger::DisableBpx(FlyUI64 dwAddress) {
        auto bpx = bpxObj.find(dwAddress);
        if (bpx != bpxObj.end()) {
            bpx->second.isEnabled = false;
            return FLY_SUCCESS;
        } else {
            return FLY_BPX_NOT_FOUND;
        }        
    }

    FlyStatus Debugger::EnableBpx(FlyUI64 dwAddress) {
        auto bpx = bpxObj.find(dwAddress);
        if (bpx != bpxObj.end()) {
            bpx->second.isEnabled = true;
            return FLY_SUCCESS;
        } else {
            return FLY_BPX_NOT_FOUND;
        }
    }

    FlyBpxStatus Debugger::IsBpxEnabled(FlyUI64 dwAddress) {
        auto bpx = bpxObj.find(dwAddress);
        if (bpx != bpxObj.end()) {
            return bpx->second.isEnabled ? FLY_BPX_ENABLED : FLY_BPX_DISABLED;
        }
        return FLY_BPX_DISABLED;
    }

    FlyStatus Debugger::DropBpx(FlyUI64 dwAddress) {
        auto bpx = bpxObj.find(dwAddress);
        if (bpx != bpxObj.end()) {
            switch (bpx->second.bxpType) {
            case FLY_BP_INT3:
                FlyUL oldProtect;
                ::VirtualProtectEx(procInfo.hProcess, (LPVOID)dwAddress, bpx->second.size, PAGE_EXECUTE_READWRITE, &oldProtect);
                WriteMemory(dwAddress, bpx->second.keepBytes, bpx->second.size);
                ::VirtualProtectEx(procInfo.hProcess, (LPVOID)dwAddress, bpx->second.size, oldProtect, &oldProtect);
                break;

            default:
                return FLY_UNKNOWN_BREAKPOINT_TYPE;
            }

            bpxObj.erase(dwAddress);
            return FLY_SUCCESS;
        }
        else {
            return FLY_BPX_NOT_FOUND;
        }
    }

    FlyStatus Debugger::TriggerBpxCallback(FlyUI64 dwAddress) {
        auto bpx = bpxObj.find(dwAddress);
        if (bpx != bpxObj.end()) {
            if (bpx->second.isEnabled) {
                FlyBpxCallback cb = *(bpx->second.bpxCallback);
                cb(dwAddress);
            }
            return FLY_SUCCESS;
        } else {
            return FLY_BPX_NOT_FOUND;
        }
    }

    FlyUI64 Debugger::GetCurrentInstructionAddress() const {
        GetThreadContext(procInfo.hThread, ctx);
#ifdef FLY_X86
        return ctx.Eip;
#endif // FLY_X86

#ifdef FLY_X64
        return ctx.Rip;
#endif // FLY_X64
    }

    FlyUI8 Debugger::GetCurrentInstructionSize() const {
        return GetInstuctionSize(GetCurrentInstructionAddress());
    }

    FlyUI8 Debugger::GetInstuctionSize(FlyUI64 dwAddress) const {
        const char *buffer = new char[MAX_INSTRUCTION_LENGTH];        

        if (FLY_IS_FAILED(ReadMemory(dwAddress, (FlyVoidPtr)buffer, MAX_INSTRUCTION_LENGTH))) {
            return 0;
        }

        ZydisDecodedInstruction instruction;
        ZydisDecoderDecodeBuffer(&decoder, buffer, MAX_INSTRUCTION_LENGTH, &instruction);

        return instruction.length;
    }
}