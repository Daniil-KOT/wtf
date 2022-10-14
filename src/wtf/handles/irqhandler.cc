#include "irqhandler.h"
#include <signal.h>

IrqHandler *IrqHandler::Instance_ = nullptr;

IrqHandler& IrqHandler::GetInstance()
{
    return *Instance_;
}

void IrqHandler::SetInstance(Server_t *Srv)
{
    static IrqHandler Instance(Srv);
    Instance_ = &Instance;
}

BOOL IrqHandler::InterruptHandler(DWORD dwCtrlType)
{
    switch (dwCtrlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        Instance_->MakeDiffs();
        exit(dwCtrlType == CTRL_C_EVENT ? SIGABRT : SIGBREAK);
    default:
        return FALSE;
    }
}

void IrqHandler::MakeDiffs()
{
    Server_->MakeCoverageDiffs();
}