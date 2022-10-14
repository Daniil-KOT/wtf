// Axel '0vercl0k' Souchet - July 10 2021
#include "../backend/backend.h"
#include "../base/targets.h"
#include <fmt/format.h>
#include <iostream>
#include <iomanip>
#include "crash_detection_umode.h"
#include "../server/mutator.h"

namespace fs = std::filesystem; 

namespace GetSerial {

constexpr bool LoggingOn = false;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("Test: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {

  //g_Backend->SetReg(Registers_t::Cr3, 0x6d4002);
  g_Backend->SetReg(Registers_t::Rdx, BufferSize);
  // Inject the fuzzed data into the snapshot for this execution
  if (!g_Backend->VirtWrite(Gva_t(g_Backend->Rcx()), 
                            Buffer, 
                            BufferSize, 
                            true)) {
    DebugPrint("Failed to write next testcase!");
    return false;
  }
  return true;
}

bool Init(const Options_t &Opts, const CpuState_t &) {

  // Stop execution if we reach the ret instruction in checkBuf(...)
  if (!g_Backend->SetBreakpoint(Gva_t(0x7ffb1bd1c059), [](Backend_t *Backend) { 
          DebugPrint("Reached function end\n");
          Backend->Stop(Ok_t());
      })) 
  {
    return false;
  }

  if (!g_Backend->SetBreakpoint(Gva_t(0x7ffb1bc05b69), [](Backend_t *Backend) {
          DebugPrint("OpenSSLX509::Init raised exception!\n");
          Backend->Stop(Ok_t());
      }))
  {
    return false;
  }

  // if (!g_Backend->SetBreakpoint(Gva_t(0x7ffb1bf8fe20), [](Backend_t *Backend) { 
  //         DebugPrint("Reached function end\n");
  //         Backend->Stop(Ok_t());
  //     })) 
  // {
  //   return false;
  // }

  // if (!g_Backend->SetBreakpoint(Gva_t(0x7ffb1bfa7510), [](Backend_t *Backend) { 
  //         DebugPrint("Reached function end\n");
  //         Backend->Stop(Ok_t());
  //     })) 
  // {
  //   return false;
  // }

  // Instrument the Windows user-mode exception dispatcher to catch access violations
  SetupUsermodeCrashDetectionHooks();

  return true;
}

// Register the target.
Target_t GetSerial("get_serial", Init, InsertTestcase);

} // namespace GetSerial