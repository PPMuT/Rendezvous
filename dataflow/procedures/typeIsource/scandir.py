# Generated at: 2026-01-10 18:15:21
# Function: scandir

import dataflow
from dataflow.data_process import inital_source_arguments 

class scandir(dataflow.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4):
        if self.block.exec_taint == 0:
            # Logic: arg2 is dst. arg1 is src.
            # int scandir(const char *dirp, struct dirent ***namelist, ...);
            # The content of the directory (arg1) is written to the list of entries (arg2).
            describe = {arg2: 'dst', arg1: 'src'} 
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
