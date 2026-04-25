# Generated at: 2026-01-10 16:48:52
# Function: nvram_get

import dataflow

class nvram_get(dataflow.SimProcedure):
    def run(self, arg1):
        if self.flow_dir == 'F' and self.block.exec_taint == 0 and self.purpose == 0:
            describe = {arg1: 'src'}
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1
        return 1

    def infer_type(self, arg1):
        self.label_variable_type(arg1, 'ptr')
        self.label_return_type('ptr')
