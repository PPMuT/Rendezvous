
import dataflow
from dataflow.data_process import inital_source_arguments

class BIO_gets(dataflow.SimProcedure):

    def run(self, bio, buf, length):

        if self.block.exec_taint == 0 and self.purpose == 0:
            describe = {bio: 'src', buf: 'dst', length: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1   

        else:
            pass
        return 1

    def infer_type(self, bio, buf, length):
        # print("infer type in BIO_gets")
        self.label_variable_type(bio, 'ptr')
        self.label_variable_type(buf, 'ptr')
        self.label_variable_type(length, 'N')
        self.label_return_type('N')
