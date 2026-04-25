# Generated at: 2026-01-10 18:15:21
# Function: readdir

import dataflow

class readdir(dataflow.SimProcedure):
    def run(self, dirp):
        if self.flow_dir == 'F' and self.block.exec_taint == 0 and self.purpose == 0:
            describe = {dirp: 'src'}
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1
        return 1

    def infer_type(self, dirp):
        self.label_variable_type(dirp, 'ptr')
        self.label_return_type('ptr')
