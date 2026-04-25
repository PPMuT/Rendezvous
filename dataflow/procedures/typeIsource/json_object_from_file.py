# Generated at: 2026-01-10 18:48:36
# Function: json_object_from_file

import dataflow

class json_object_from_file(dataflow.SimProcedure):
    def run(self, filename):
        if self.flow_dir == 'F' and self.block.exec_taint == 0 and self.purpose == 0:
            describe = {filename: 'src'}
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1
        return 1

    def infer_type(self, filename):
        self.label_variable_type(filename, 'ptr')
        self.label_return_type('ptr')
