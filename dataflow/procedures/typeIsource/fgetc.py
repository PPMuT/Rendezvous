# Generated at: 2026-01-10 18:48:36
# Function: fgetc

import dataflow

class fgetc(dataflow.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4):
        if self.flow_dir == 'F' and self.block.exec_taint == 0 and self.purpose == 0:
            describe = {arg1: 'src'}
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1
        return 1

    def infer_type(self, arg1, arg2, arg3, arg4):
        self.label_variable_type(arg1, 'ptr')
        self.label_return_type('int')
