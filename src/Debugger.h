#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_map>

#include <Zydis/Zydis.h>

#include "Fly.h"
#include "ntddk.h"

#define MAX_INSTRUCTION_LENGTH 15

namespace fly {
    struct BPX {
        FlyBpxType bxpType;
        FlyBpxCallback *bpxCallback;
        FlyBool isEnabled;
        FlyUI16 size;
        char* keepBytes;
    };

    static const FlyUI8 UD2BreakPoint[2] = { 0x0F, 0x0B };
    static const FlyUI8 INT3BreakPoint[1] = { 0xCC };
    static const FlyUI8 INT3LongBreakPoint[2] = { 0xCD, 0x03 };

    /*
      Debugger class is implements via regular Windows Debug Api.
    */
    class Debugger {
    private:
        FlyVoidPtr mainThreadHandle;
        FlyUI64 mainThreadId;
        ZydisDecoder decoder;
        mutable CONTEXT ctx;
        PEB peb;
        PROCESS_BASIC_INFORMATION pbi;
        PROCESS_INFORMATION procInfo;
        STARTUPINFO startupInfo;
        DEBUG_EVENT debugEvent;
        std::atomic<FlyStatus> initStatus;
        std::atomic<FlyBool> bContinueDebugging;
        std::thread debugLoopThread;
        FlyBool redirectStdoutToNull;
        std::unordered_map<FlyUI64, BPX> bpxObj;

        void InitDebugThread(const std::wstring &inputFileName, const std::wstring &cmd, const std::wstring &currentPath);
        void EnterDebugLoop();

    public:
        Debugger();
        ~Debugger();

        // Debugger
        FlyStatus InitDebug(const std::wstring &inputFileName, const std::wstring &cmd, const std::wstring &currentPath);
        FlyStatus AttachToProcess(FlyUI64 processId);
        FlyUI64 GetImageBaseFromPEB() const;
        FlyStatus ReadMemory(FlyUI64 dwAddress, FlyVoidPtr buffer, size_t length) const;
        FlyStatus WriteMemory(FlyUI64 dwAddress, FlyVoidPtr buffer, size_t length) const;
        FlyStatus GetThreadContext(FlyVoidPtr hThread, CONTEXT &ctx) const;
        FlyStatus SetThreadContext(FlyVoidPtr hThread, const CONTEXT &ctx) const;
        void RedirectStdoutToNull();
        void Run();
        void Pause();
        FlyStatus StopDebug();

        // Debugger.Tracer
        FlyStatus SetBpx(FlyUI64 dwAddress, FlyBpxType bpxType, FlyBpxCallback &bpxCallback);
        FlyStatus DisableBpx(FlyUI64 dwAddress);
        FlyStatus EnableBpx(FlyUI64 dwAddress);
        FlyBpxStatus IsBpxEnabled(FlyUI64 dwAddress);
        FlyStatus DropBpx(FlyUI64 dwAddress);
        FlyStatus TriggerBpxCallback(FlyUI64 dwAddress);
        FlyUI64 GetCurrentInstructionAddress() const;
        FlyUI8 GetCurrentInstructionSize() const;
        FlyUI8 GetInstuctionSize(FlyUI64 dwAddress) const;
    };
}