# new add in 2026-1-9
import dataflow
from dataflow.data_process import inital_source_arguments

class ioctl(dataflow.SimProcedure):
    # 根据 'Third'，我们将第三个参数命名为 argp，并标记为 'dst'
    def run(self, fd, request, argp):
        # 检查执行流方向、是否已污点标记等
        if self.block.exec_taint == 0 and self.purpose == 0:
            # fd 是数据来源 ('src')，argp 是接收污点的参数 ('dst')
            # request 通常是命令码，可以不参与污点传播，或者作为约束
            describe = {fd: 'src', argp: 'dst'} 
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        else:
            pass
        return 1

    def infer_type(self, fd, request, argp):
        self.label_variable_type(fd, 'N')
        self.label_variable_type(request, 'N')
        self.label_variable_type(argp, 'ptr') # 指针类型
        self.label_return_type("N")