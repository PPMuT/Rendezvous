
import dataflow
from dataflow.data_process import inital_source_arguments

class recvfrom(dataflow.SimProcedure):
    def run(self, fd, buf, length, flags, src_addr, addrlen):

        if self.block.exec_taint == 0 and self.purpose == 0:
            describe = {fd: 'src', buf: 'dst', length: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1

        else:
            pass
        return 1

    def infer_type(self, fd, buf, length, flags, src_addr, addrlen):
        self.label_variable_type(fd, 'N')
        self.label_variable_type(buf, 'ptr')
        self.label_variable_type(length, 'N')
        self.label_variable_type(flags, 'N')
        self.label_return_type('N')
