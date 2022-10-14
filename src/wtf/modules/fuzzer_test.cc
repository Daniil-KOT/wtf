// Axel '0vercl0k' Souchet - July 10 2021
#include "../backend/backend.h"
#include "../base/targets.h"
#include <fmt/format.h>
#include <iostream>
#include <iomanip>
#include "crash_detection_umode.h"
#include "../server/mutator.h"

namespace fs = std::filesystem;

namespace Test {

constexpr bool LoggingOn = false;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("Test: ");
    fmt::print(fmt::runtime(Format), args...); 
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {

  // Inject the fuzzed data into the snapshot for this execution
  if (!g_Backend->VirtWrite(Gva_t(g_Backend->Rax()), 
                            Buffer, 
                            BufferSize <= 10 ? BufferSize : 10 , 
                            true)) {
    DebugPrint("Failed to write next testcase!");
    return false;
  }
  return true;
}

bool Init(const Options_t &Opts, const CpuState_t &) {
  
  // Stop execution if we reach the ret instruction in checkBuf(...)
  if (!g_Backend->SetBreakpoint(Gva_t(0x7ff77b974036), [](Backend_t *Backend) { 
          DebugPrint("Reached function end\n");
          Backend->Stop(Ok_t());
      })) 
  {
    return false;
  }

  // Instrument the Windows user-mode exception dispatcher to catch access violations
  SetupUsermodeCrashDetectionHooks();

  return true;
}

// Register the target.
Target_t Test("test", Init, InsertTestcase);

} // namespace Test