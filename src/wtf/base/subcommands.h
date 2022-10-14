// Axel '0vercl0k' Souchet - April 5 2020
#pragma once
#include "../globals/globals.h"
#include "../base/targets.h"
#include "../server/server.h"

//
// Handles the 'master' subcommand.
//

int MasterSubcommand(Server_t &Srv, const Target_t &Target);

//
// Handles the 'run' subcommand.
//

int RunSubcommand(const Options_t &Opts, const Target_t &Target,
                  const CpuState_t &CpuState);

//
// Handles the 'fuzz' subcommand.
//

int FuzzSubcommand(const Options_t &Opts, const Target_t &Target,
                   const CpuState_t &CpuState);
