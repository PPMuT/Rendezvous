# Rendezvous


## Overview

Rendezvous is a static taint analysis framework for firmware binaries. The three main entry scripts in this repository are:

- `source.py`: identify taint source functions
- `sink.py`: identify taint sink functions
- `main.py`: run taint propagation analysis

It is recommended to run all scripts from the repository root.

## Environment

- Python 3.8.10
  - Install dependencies with `pip install -r requirements.txt`
- Binary Ninja Commercial 3.5.4526
  - `source.py` and `sink.py` call the Binary Ninja Python API directly from `python3`, which is a headless/batch workflow. According to the official Binary Ninja documentation, this requires the Commercial or Ultimate edition.
  - Python API installation guide: <https://docs.binary.ninja/dev/batch.html#install-the-api>
- IDA Pro 7.5
- `api_config.json`
  - `source.py` and `sink.py` read the `source` / `sink` entries from this file. Configure it with your own OpenAI-compatible API endpoint, key, and model before running the scripts.

## Repository Layout

- `source.py`: taint source identification script
- `sink.py`: taint sink identification script
- `main.py`: entry point for taint propagation
- `dataflow/procedures/customSink/`: sink function summaries
- `dataflow/procedures/typeIIsource/`: Type II source function summaries
- `dataflow/procedures/typeIsource/`: Type I source function summaries
- `firmware-binaries/`: firmware binaries to analyze
- `data/ida_data/`: CFG information exported from IDA, organized by the required `-n/--name` folder name
- `data/result_data/`: taint propagation results, stored as `<name>.json` where `<name>` comes from `-n/--name`

For a new firmware sample, update the summary files in the directories above according to the outputs of `source.py` and `sink.py`.

## 1. Taint Source Identification

- `path_to_binary`: path to the target binary
- `path_to_firmware_root`: root directory of the unpacked firmware filesystem

```bash
python3 source.py path_to_binary path_to_firmware_root
# python3 source.py /home/jylsec/Desktop/code/netgear_r6300/root/usr/sbin/httpd /home/jylsec/Desktop/code/netgear_r6300/root
```

- Output: in the resulting dictionary, each `key` is a taint source function and each `value` is the parameter index or return value carrying the taint source
- Rendezvous uses two `SimProcedure` templates for taint sources:
  - Type I: the taint source is in a function argument, for example `SSL_read`
  - Type II: the taint source is in the return value, for example `getenv`

```python
# rendezvous/dataflow/procedures/typeIIsource/getenv.py
import dataflow

class getenv(dataflow.SimProcedure):
    def run(self, name):
        if self.flow_dir == 'F' and self.block.exec_taint == 0 and self.purpose == 0:
            describe = {name: 'src'}
            self.initial_ret_taint_source(describe)
            self.block.exec_taint = 1
        return 1

    def infer_type(self, name):
        self.label_variable_type(name, 'ptr')
        self.label_return_type('ptr')
```

```python
# rendezvous/dataflow/procedures/typeIsource/SSL_read.py
import dataflow
from dataflow.data_process import inital_source_arguments

class SSL_read(dataflow.SimProcedure):
    def run(self, ssl, buf, num):
        if self.block.exec_taint == 0:
            describe = {ssl: 'src', buf: 'dst', num: 'length'}
            inital_source_arguments(self.block, describe)
            self.block.exec_taint = 1
        return 1

    def infer_type(self, ssl, buf, num):
        self.label_variable_type(ssl, 'ptr')
        self.label_variable_type(buf, 'ptr')
        self.label_variable_type(num, 'N')
        self.label_return_type('N')
```

Based on the two templates above, when adding a new taint source summary for `funcA`, update the following parts:

1. Change `class SSL_read(dataflow.SimProcedure):` to `class funcA(dataflow.SimProcedure):`
2. Change `def run(self, ssl, buf, num):` so that the argument count matches `funcA`; parameter names can be chosen freely
3. `describe = {ssl: 'src', buf: 'dst', num: 'length'}; inital_source_arguments(self.block, describe)`
   - For argument-based taint sources, `src` and `dst` are required
   - `src` specifies the data origin and `dst` marks the tainted argument
   - `length` is optional and can be used for a length constraint
4. `describe = {name: 'src'}; self.initial_ret_taint_source(describe)`
   - For return-based taint sources, `src` is required
   - You may also add `length` for a length constraint
5. Change `def infer_type(self, ssl, buf, num):` so that the argument count matches `funcA`; parameter names can be chosen freely
6. In `infer_type`, label each argument and the return value with a type using statements such as `self.label_variable_type(buf, 'ptr')`; if you are unsure, using `ptr` everywhere is acceptable
7. Place the new summary file in:
   - `rendezvous/dataflow/procedures/typeIsource/funcA.py`
   - or `rendezvous/dataflow/procedures/typeIIsource/funcA.py`

## 2. Taint Sink Identification

- `path_to_binary`: path to the target binary
- `path_to_firmware_root`: root directory of the unpacked firmware filesystem

```bash
python3 sink.py path_to_binary path_to_firmware_root
# python3 sink.py /home/jylsec/Desktop/code/netgear_r6300/root/usr/sbin/httpd /home/jylsec/Desktop/code/netgear_r6300/root
```

- Output: in the resulting dictionary, each `key` is a taint sink function and each `value` is the argument position of the sink
- The sink summary template is shown below. For a new sink function, besides updating the argument lists and types in `def run(...)` and `def infer_type(...)`, you also need to change `arg1 in trace_sims` to `argN in trace_sims`, where `argN` is the vulnerable argument

```python
class popen(dataflow.SimProcedure):
    def run(self, arg1, arg2):
        if self.flow_dir == 'F' and self.purpose == 0:
            for trace_expr in self.block.forward_exprs:
                trace_sims = trace_expr.expr.sims
                trace_ast = trace_expr.expr.ast
                flag = trace_expr.expr.flag
                if trace_ast.op == 'BVS' and flag & 0x100 and arg1 in trace_sims:
                    self.block.is_tainted = 2
                    weaks_command_exec[self.block.addr].append(trace_expr)
        return 1

    def infer_type(self, arg1, arg2):
        self.label_variable_type(arg1, 'ptr')
        self.label_variable_type(arg2, 'ptr')
        self.label_return_type('ptr')
```

## 3. Taint Propagation

1. Open the target binary in IDA Pro 7.5, then choose `File -> Script file` and run:
   - `dataflow/ida_plugin/arm_cfg.py`
   - or `dataflow/ida_plugin/mips_cfg.py`

   This generates the CFG information file (`.json`) in the same directory as the target binary.

2. When running `main.py`, you must provide `-n/--name`. This name is used in two places:
   - The target binary's two IDA CFG JSON files must be placed under `data/ida_data/<name>/`
   - The taint analysis result will be written to `data/result_data/<name>.json`

   For example, if you want to analyze the `httpd` binary from the ASUS AX6000 firmware, and you have exported the two CFG JSON files with IDA, place them in `data/ida_data/ASUS_AX6000/`, then run:

```bash
python3 main.py -f firmware-binaries/asus_ax6000/httpd -n ASUS_AX6000 -t
```

After the analysis finishes, the vulnerability report will be written to `data/result_data/ASUS_AX6000.json`.
