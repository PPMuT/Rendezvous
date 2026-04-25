import dataflow
from dataflow.data_process import inital_source_arguments

class SSL_read(dataflow.SimProcedure):
    def run(self, ssl, buf, num):
        if self.block.exec_taint == 0:
            describe = {ssl: 'src', buf: 'dst', num: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, ssl, buf, num):
        self.label_variable_type(ssl, 'ptr')
        self.label_variable_type(buf, 'ptr')
        self.label_variable_type(num, 'N')
        self.label_return_type('N')