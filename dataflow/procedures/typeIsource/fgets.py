
import dataflow
from dataflow.data_process import inital_source_arguments

class fgets(dataflow.SimProcedure):
    def run(self, s, n, stream):
        if self.block.exec_taint == 0 and self.purpose == 0:
            describe = {stream: 'src', s: 'dst', n: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, s, n, stream):
        self.label_variable_type(s, 'ptr')
        self.label_variable_type(stream, 'ptr')
        self.label_variable_type(n, 'N')
        self.label_return_type('ptr')
