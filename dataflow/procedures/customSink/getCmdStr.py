# new add in 2026-1-9
import dataflow
# 引入用于记录漏洞的全局变量 (根据 system.py)
from dataflow.data_collector import weaks_command_exec

class getCmdStr(dataflow.SimProcedure):
    # 假设只有一个参数 cmd，或者多个参数中第一个是 cmd
    def run(self, cmd):
        if self.flow_dir == 'F' and self.purpose == 0:
            for trace_expr in self.block.forward_exprs:
                trace_sims = trace_expr.expr.sims
                trace_ast = trace_expr.expr.ast
                flag = trace_expr.expr.flag

                # 检查:
                # 1. 约束类型为 BVS (BitVector Symbol)
                # 2. flag & 0x100 (通常表示污点标记位)
                # 3. 关键修改: cmd (第一个参数) 是否在 trace_sims 中
                if trace_ast.op == 'BVS' and flag & 0x100 and cmd in trace_sims:
                    self.block.is_tainted = 2 # 标记为检测到漏洞
                    weaks_command_exec[self.block.addr].append(trace_expr)
        return 1

    def infer_type(self, cmd):
        self.label_variable_type(cmd, 'ptr')
        self.label_return_type('N') # 根据实际情况调整返回类型，通常 sink 返回类型不重要