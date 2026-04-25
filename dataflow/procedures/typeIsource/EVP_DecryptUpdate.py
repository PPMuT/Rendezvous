# Generated at: 2026-01-10 18:48:36
# Function: EVP_DecryptUpdate

import dataflow
from dataflow.data_process import inital_source_arguments

class EVP_DecryptUpdate(dataflow.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4, arg5):
        # int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
        # arg1: ctx
        # arg2: out (dst)
        # arg3: outl (ptr to out len)
        # arg4: in (src)
        # arg5: inl (in len)
        if self.block.exec_taint == 0:
            describe = {arg2: 'dst', arg4: 'src', arg5: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, arg1, arg2, arg3, arg4, arg5):
        self.label_variable_type(arg1, 'ptr')
        self.label_variable_type(arg2, 'ptr')
        self.label_variable_type(arg3, 'ptr')
        self.label_variable_type(arg4, 'ptr')
        self.label_variable_type(arg5, 'N')
        self.label_return_type('N')
