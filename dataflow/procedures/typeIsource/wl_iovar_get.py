# Generated at: 2026-01-10 18:15:21
# Function: wl_iovar_get

import dataflow
from dataflow.data_process import inital_source_arguments

class wl_iovar_get(dataflow.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4):
        if self.block.exec_taint == 0:
            # Logic: arg3 is the destination buffer, arg4 is the length.
            # The source is external (hardware/driver state).
            describe = {arg3: 'dst', arg4: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, arg1, arg2, arg3, arg4):
        self.label_variable_type(arg1, 'ptr')
        self.label_variable_type(arg2, 'ptr')
        self.label_variable_type(arg3, 'ptr')
        self.label_variable_type(arg4, 'ptr')
        self.label_return_type('N')
