#pragma once

#include "../server/server.h"
#include <Windows.h>

class IrqHandler
{
public:
    static IrqHandler& GetInstance();
    static void SetInstance(Server_t *Srv);
    static BOOL WINAPI InterruptHandler(_In_ DWORD dwCtrlType);

private:
    IrqHandler(Server_t *Srv)
        : Server_(Srv)
    {}

    IrqHandler(const IrqHandler&) = delete;
    IrqHandler& operator=(const IrqHandler&) = delete;
    void MakeDiffs();
    Server_t *Server_;
    static IrqHandler *Instance_;
};
