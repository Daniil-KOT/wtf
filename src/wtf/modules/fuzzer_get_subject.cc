// Axel '0vercl0k' Souchet - July 10 2021
#include "../backend/backend.h"
#include "../base/targets.h"
#include <fmt/format.h>
#include <iostream>
#include <iomanip>
#include "crash_detection_umode.h"
#include "../server/mutator.h"

namespace fs = std::filesystem;

namespace GetSubject {

constexpr bool LoggingOn = false;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("Test: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {

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
  
  // getCertificateAttribute instruction after switch case
  if (!g_Backend->SetBreakpoint(Gva_t(0x7ffc1116c059), [](Backend_t *Backend) { 
          DebugPrint("Reached function end\n");
          Backend->Stop(Ok_t());
      })) 
  {
    return false;
  }

  // OpenSSLX509 exception
  if (!g_Backend->SetBreakpoint(Gva_t(0x7ffb1bc05b69), [](Backend_t *Backend) {
          DebugPrint("OpenSSLX509::Init raised exception!\n");
          Backend->Stop(Ok_t());
      }))
  {
    return false;
  }

  // // getCertificateAttribute catch 1
  // if (!g_Backend->SetBreakpoint(Gva_t(0x7ffc113f7510), [](Backend_t *Backend) { 
  //         DebugPrint("getCertificateAttribute catch 1!\n");
  //         Backend->Stop(Ok_t());
  //     })) 
  // {
  //   return false;
  // }

  // // getCertificateAttribute catch 2
  // if (!g_Backend->SetBreakpoint(Gva_t(0x7ffc113dfe20), [](Backend_t *Backend) { 
  //         DebugPrint("getCertificateAttribute catch 2!\n");
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
Target_t GetSubject("get_subject", Init, InsertTestcase);

} // namespace GetSubject