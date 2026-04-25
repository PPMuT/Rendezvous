# Generated at: 2026-01-10 18:21:30
# Function: bwdpi_monitor_nonips

import dataflow
from dataflow.procedures.stubs.format_parser import FormatParser
from dataflow.data_collector import weaks_command_exec, weaks_copy

class bwdpi_monitor_nonips(dataflow.SimProcedure): 
    def run(self, arg1, arg2, arg3, arg4):
        if self.flow_dir == 'F' and self.purpose == 0:
            danger_names = ['arg1', 'arg2', 'arg3']
            for trace_expr in self.block.forward_exprs:
                trace_sims = getattr(trace_expr.expr, 'sims', [])
                trace_ast = getattr(trace_expr.expr, 'ast', None)
                flag = getattr(trace_expr.expr, 'flag', 0)
                
                if trace_ast is not None and getattr(trace_ast, 'op', None) == 'BVS' and (flag & 0x100):
                    for sim in trace_sims:
                        sim_name = getattr(sim, 'name', None) or getattr(sim, 'arg', None)
                        if sim_name in danger_names:
                            self.block.is_tainted = 2
                            weaks_command_exec.setdefault(self.block.addr, []).append(trace_expr)
        return 1

    def infer_type(self, arg1, arg2, arg3, arg4):
        self.label_variable_type(arg1, 'ptr')
        self.label_variable_type(arg2, 'ptr')
        self.label_variable_type(arg3, 'ptr')
        self.label_variable_type(arg4, 'ptr')
        self.label_return_type('ptr')
