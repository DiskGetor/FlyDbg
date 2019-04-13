#ifndef FLY_H
#define FLY_H

#include <windows.h>
#include <functional>

namespace fly {
    enum FlyStatus {
        FLY_SUCCESS = 0,
        FLY_PENDING,
        FLY_ALREADY_LOADED,
        FLY_ERROR_CREATING_PROCESS,
        FLY_ERROR_READING_CONTEXT,
        FLY_ERROR_WRITING_CONTEXT,
        FLY_ERROR_OPENING_MAIN_THREAD,
        FLY_ERROR_READING_MEMORY,
        FLY_ERROR_WRITING_MEMORY,
        FLY_ERROR_SEND_QUERY_INFORMATION,
        FLY_ERROR_READING_PEB,
        FLY_UNKNOWN_ERROR,
        FLY_FILE_NOT_FOUND,
        FLY_BPX_NOT_FOUND,
        FLY_UNKNOWN_BREAKPOINT_TYPE,
    };

    enum FlyBpxType {
        FLY_BP_INT3 = 0,
        FLY_BP_LONG_INT3,
        FLY_BP_UD2,
    };

    enum FlyBpxStatus {
        FLY_BPX_DISABLED = 0,
        FLY_BPX_ENABLED,
    };

    typedef void* FlyVoidPtr;

    typedef bool FlyBool;

    typedef size_t FlySizeT;

    typedef unsigned long FlyUL;
    typedef char FlyI8;
    typedef short int FlyI16;
    typedef int FlyI32;
    typedef long long FlyI64;

    typedef unsigned char FlyUI8;
    typedef unsigned short int FlyUI16;
    typedef unsigned int FlyUI32;
    typedef unsigned long long FlyUI64;

    typedef std::function<void(FlyUI64 dwAddress)> FlyBpxCallback;

    #define FLY_IS_SUCCESS(cond) (cond == 0)
    #define FLY_IS_FAILED(cond) (cond != 0)

    #define FLY_ASSERT(arg) (assert(arg))

    #define FLY_SLEEP(ms) (std::this_thread::sleep_for(std::chrono::milliseconds(ms)))

    /// Architecture detection

    #if defined(_M_AMD64) || defined(__x86_64__)
    #   define FLY_X64
    #elif defined(_M_IX86) || defined(__i386__)
    #   define FLY_X86
    #else
    #   error "Unsupported architecture"
    #endif
}

#endif