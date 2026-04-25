
import dataflow
from dataflow.data_process import inital_source_arguments

class read(dataflow.SimProcedure):
    def run(self, fd, buf, nbytes):
        if self.block.exec_taint == 0 and self.purpose == 0:
            describe = {fd: 'src', buf: 'dst', nbytes: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1

        else:
            pass

        return 1

    def infer_type(self, fd, buf, nbytes):
        # print("infer type in read")
        self.label_variable_type(fd, 'N')
        self.label_variable_type(buf, 'ptr')
        self.label_variable_type(nbytes, 'N')
        self.label_return_type("N")
