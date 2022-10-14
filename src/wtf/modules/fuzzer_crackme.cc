#include "../backend/backend.h"
#include "../base/targets.h"
#include <fmt/format.h>
#include <iostream>
#include <iomanip>
#include "crash_detection_umode.h"
#include "../server/mutator.h" 

namespace fs = std::filesystem;

namespace Crackme {

constexpr bool LoggingOn = false;

// Keys ordinal number counter
static uint64_t keys = 0;

template <typename... Args_t>
void DebugPrint(const char *Format, const Args_t &...args) {
  if constexpr (LoggingOn) {
    fmt::print("Crackme: ");
    fmt::print(fmt::runtime(Format), args...);
  }
}

bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
  
  /* 
   * For some reason cr3 reg is dumped with a DirectoryTableBase addr
   * so setting a UserDirectoryTableBase addr here
   */
  //g_Backend->SetReg(Registers_t::Cr3, 0x4ffd2001);

  g_Backend->SetReg(Registers_t::Rdx, BufferSize > 19 ? 19 : BufferSize);
  
  // Inject the fuzzed data into the snapshot for this execution
  if (!g_Backend->VirtWrite(Gva_t(g_Backend->Rcx()), 
                            Buffer, 
                            BufferSize > 19 ? 19 : BufferSize, 
                            true)) {
    DebugPrint("Failed to write next testcase!\n");
    return false;
  }

  return true;
}

/*
 * Defined for crackme module to avoid using other macro
 * same define is present in utils.cc.
 */
#define CORRECT_KEY_FOUND   0xccdef

bool Init(const Options_t &Opts, const CpuState_t &) {

  // Ret instruction after check len fail
  if (!g_Backend->SetBreakpoint(Gva_t(0x140001012), [](Backend_t *Backend) { 
          DebugPrint("Buffer len was less than 19 or there was no '-'\n");
          Backend->Stop(Ok_t());
      })) 
  {
    return false;
  }

  // Check fail instruction
  if (!g_Backend->SetBreakpoint(Gva_t(0x140001108), [](Backend_t *Backend) { 
          DebugPrint("Wrong key!\n");
          Backend->Stop(Ok_t());
      })) 
  {
    return false;
  }

  // Check successed
  if (!g_Backend->SetBreakpoint(Gva_t(0x1400010fc), [](Backend_t *Backend) { 
          DebugPrint("Correct key found!\n");
          
          /*
           * Using SaveCrash(...) just because there are no other
           * more or less convenient options to save corpus.
           * Also passing not an address as a 1st arg,
           * but an ordinal number of a key.
           * 2nd arg is a custom macro defined above.
           */
          Backend->SaveCrash(Gva_t(++keys), CORRECT_KEY_FOUND);
      })) 
  {
    return false;
  }

  // Instrument the Windows user-mode exception dispatcher to catch access violations
  SetupUsermodeCrashDetectionHooks();

  return true;
}

/*
class DigitsMutator_t : public Mutator_t
{
  std::unique_ptr<uint8_t[]> ScratchBuffer__;
  span_u8 ScratchBuffer_;
  size_t TestcaseMaxSize_ = 0;
  std::mt19937_64 &Rng_;
  fuzzer::MutationDispatcher Mut_;

  public:
    static std::unique_ptr<Mutator_t> Create(std::mt19937_64 &Rng,
                                           const size_t TestcaseMaxSize) {
    return std::make_unique<DigitsMutator_t>(Rng, TestcaseMaxSize);
  }

  explicit DigitsMutator_t(std::mt19937_64 &Rng, const size_t TestcaseMaxSize)
      : Rng_(Rng), TestcaseMaxSize_(TestcaseMaxSize) {
    ScratchBuffer__ = std::make_unique<uint8_t[]>(_1MB);
    ScratchBuffer_ = {ScratchBuffer__.get(), _1MB};
  }

  std::string GetNewTestcase(const Corpus_t &Corpus) override {

    const Testcase_t *Testcase = Corpus.PickTestcase();
    if (!Testcase) {
      fmt::print("The corpus is empty, exiting\n");
      std::abort();
    }

    memcpy(ScratchBuffer_.data(), Testcase->Buffer_.get(),
           Testcase->BufferSize_);
    const size_t NewSize = Mut_.Mutate_ChangeASCIIInteger(ScratchBuffer_.data(), 
                                                          Testcase->BufferSize_,
                                                          ScratchBuffer_.size_bytes());
    std::string NewTestcase((char *)ScratchBuffer_.data(), NewSize);
    return NewTestcase;
  }
};
*/

// Register the target.
Target_t Crackme("crackme", Init, InsertTestcase);

} // namespace Crackme