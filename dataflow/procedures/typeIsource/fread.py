
import dataflow
from dataflow.data_process import inital_source_arguments

class fread(dataflow.SimProcedure):

    def run(self, ptr, size, n, stream):
        if self.block.exec_taint == 0 and self.purpose == 0:
            describe = {stream: 'src', ptr: 'dst', n: 'length', size: 'size'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, ptr, size, n, stream):
        self.label_variable_type(ptr, 'ptr')
        self.label_variable_type(size, 'N')
        self.label_variable_type(n, 'N')
        self.label_variable_type(stream, 'N')
        self.label_return_type('N')
