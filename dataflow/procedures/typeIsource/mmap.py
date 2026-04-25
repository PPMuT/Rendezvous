# new add in 2026-1-9
import dataflow

class mmap(dataflow.SimProcedure):
    # mmap(addr, length, prot, flags, fd, offset)
    def run(self, addr, length, prot, flags, fd, offset):
        if self.flow_dir == 'F' and self.block.exec_taint == 0 and self.purpose == 0:
            # fd 是数据来源 ('src')
            describe = {fd: 'src'}
            # 使用 initial_ret_taint_source 将返回值标记为污点
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, addr, length, prot, flags, fd, offset):
        self.label_variable_type(addr, 'ptr')
        self.label_variable_type(length, 'N')
        self.label_variable_type(prot, 'N')
        self.label_variable_type(flags, 'N')
        self.label_variable_type(fd, 'N')
        self.label_variable_type(offset, 'N')
        self.label_return_type('ptr') # 返回映射内存的指针