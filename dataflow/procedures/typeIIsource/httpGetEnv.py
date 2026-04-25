import dataflow

class httpGetEnv(dataflow.SimProcedure):

    def run(self, entry, name):
        if self.block.exec_taint == 0:
            describe = {name: 'src'}
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1

        else:
            pass
        return 1

    def infer_type(self, entry, name):
        self.label_variable_type(name, 'ptr')
        self.label_variable_type(entry, 'ptr')
        self.label_return_type('ptr')

