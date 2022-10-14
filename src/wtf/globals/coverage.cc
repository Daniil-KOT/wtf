#include "coverage.h"
#include <iomanip>
#include <set>

CoverageCounter::CoverageCounter()
{
    fmt::print("Binary name was not provided, coverage won't be calculated.\n");
    OverallCov_ = 0;
    HarnessBinary_ = nullptr;
    std::string Encoded_ = "";
    bool HasStats_ = false;
}

CoverageCounter::CoverageCounter(const MasterOptions_t &Opts)
{
    if (Opts.BinaryName.empty())
    {
        CoverageCounter();
        return;
    }

    HarnessBinary_->open(Opts.TargetPath.string() + "/harness/" + Opts.BinaryName, std::ios::binary);

    if (!HarnessBinary_)
    {
        fmt::print("Cannot find binary: \"{}/harness/{}\".\n"
                   "Exiting.\n", Opts.TargetPath.string(), Opts.BinaryName);
        abort();
    }
    std::stringstream Buf;
    Buf << HarnessBinary_->rdbuf();
    Encoded_ = Buf.str();
    HasStats_ = CalculateOverallCov();
}

CoverageCounter::~CoverageCounter()
{
    if (HarnessBinary_->is_open())
    {
        HarnessBinary_->close();
    }
}

bool CoverageCounter::CalculateOverallCov()
{
    csh Handle;
    cs_insn* Instr;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &Handle) != CS_ERR_OK)
    {
        return false;
    }
    
    OverallCov_ = 0;
    cs_option(Handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    size_t Count = cs_disasm(Handle, (uint8_t*)Encoded_.data(), Encoded_.size(), 0x1000, 0, &Instr);
    std::ofstream out("1.txt");
    if (Count > 0)
    {
        char delim[1]{':'};
        char sep[1]{'\n'};
        if (!out)
        {
            fmt::print("Not open");
        }

        for (size_t i = 0; i < Count; ++i)
        {
            if (Instr[i].mnemonic)
            {
                if (out)
                {
                    auto addr = fmt::format("{:#x}", Instr[i].address);
                    addr += ':';
                    out.write(addr.data(), addr.length());
                    out.write(Instr[i].mnemonic, std::strlen(Instr[i].mnemonic));
                    out.write(delim, 1);
                    out.write(Instr[i].op_str, std::strlen(Instr[i].op_str));
                    out.write(sep, 1);
                }
                OverallCov_ += 1;
            }
        }
        cs_free(Instr, Count);
    }
    else
    {
        fmt::print("Failed to disassemble the given code!");
        cs_close(&Handle);
        return false;
    }
    out.close();
    cs_close(&Handle);
    return true;
}