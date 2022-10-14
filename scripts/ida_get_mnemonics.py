import sys
sys.path.append("E:\\IDA\\python\\3")

import idautils
import idc

idc.auto_wait()
for function_ea in idautils.Functions():
    for ins in idautils.FuncItems(function_ea):
        if idaapi.is_code(idaapi.get_full_flags(ins)):
            cmd = idc.GetDisasm(ins)
            mnem = cmd.split(' ')[0]
            print(mnem)