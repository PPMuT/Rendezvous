# Generated at: 2026-01-10 18:15:21
# Function: uname

import dataflow
from dataflow.data_process import inital_source_arguments

class uname(dataflow.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4):
        # int uname(struct utsname *buf);
        # The uname() function shall place all the information in the structure pointed to by buf.
        if self.block.exec_taint == 0:
            # arg1 is the destination buffer
            describe = {arg1: 'dst', arg1: 'src'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, arg1, arg2, arg3, arg4):
        self.label_variable_type(arg1, 'ptr')
        # Unused arguments, but labeling for completeness as per some conventions
        self.label_variable_type(arg2, 'ptr')
        self.label_variable_type(arg3, 'ptr')
        self.label_variable_type(arg4, 'ptr')
        self.label_return_type('N')
