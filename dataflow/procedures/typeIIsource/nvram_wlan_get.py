# new add in 2026-1-9
import dataflow

class nvram_wlan_get(dataflow.SimProcedure):
    def run(self, name):
        if self.flow_dir == 'F' and self.block.exec_taint == 0 and self.purpose == 0:
            # name 是数据的索引/来源 ('src')
            describe = {name: 'src'}
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, name):
        self.label_variable_type(name, 'ptr')
        self.label_return_type('ptr')