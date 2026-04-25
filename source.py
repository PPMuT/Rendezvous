import re
import binaryninja
import sys
from elftools.elf.elffile import ELFFile
import os
import magic
from collections import OrderedDict

from openai import OpenAI
import json
from termcolor import colored
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Union

from binaryninja import (
    load,
    Function,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    MediumLevelILImport,
    Variable,
    SSAVariable,
    InstructionTextTokenType,
)

API_CONFIG_PATH = Path(__file__).with_name("api_config.json")
_API_CONFIG_CACHE: Dict[str, Any] | None = None


def load_api_config() -> Dict[str, Any]:
    global _API_CONFIG_CACHE
    if _API_CONFIG_CACHE is None:
        with API_CONFIG_PATH.open("r", encoding="utf-8") as config_file:
            _API_CONFIG_CACHE = json.load(config_file)
    return _API_CONFIG_CACHE


def get_llm_config(section: str) -> Dict[str, Any]:
    config = load_api_config().get(section)
    if not isinstance(config, dict):
        raise KeyError(f"Missing '{section}' section in {API_CONFIG_PATH}")

    required_keys = {
        "api_key",
        "base_url",
        "model",
    }
    missing_keys = sorted(required_keys - set(config))
    if missing_keys:
        raise KeyError(
            f"Missing keys in {API_CONFIG_PATH}:{section}: {', '.join(missing_keys)}"
        )
    return config

class LRUCache:
    def __init__(self, capacity: int):
        self.cache = OrderedDict()
        self.capacity = capacity

    def get(self, key: str):
        if key not in self.cache:
            return None
        self.cache.move_to_end(key)
        return self.cache[key]

    def put(self, key: str, value: str):
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        if len(self.cache) > self.capacity:
            self.cache.popitem(last=False)


typeIsystemInstruction = """You are an experienced IoT firmware vulnerability analyst tasked with analyzing C functions that may serve as taint source function. For each given function name, you should perform the following steps in sequence:
1. Check if the function is part of a C standard library or a common third-party library.
2. If the function is confirmed to be a standard or third-party library function, determine whether it directly reads a contiguous block of data from an external source into a buffer without explicitly parsing the data's internal structure(like BIO_read,recv,recvfrom,SSL_read,fgets,fread,read,BIO_gets)
3. If the function’s functionality matches the requirement, identify which function parameter or return value represents the buffer that stores the read data.
Only Output all functions that may serve as taint source function in json format:{"Function_name1": "First | Second | Third | Fourth | Return","Function_name2": "First | Second | Third | Fourth | Return"}. Each key in the JSON represents a function name, and each corresponding value indicates which function argument or the return value serves as the buffer that stores the data.
Dont output the function that just establish a connection or open a resource for later reading(like open,fopen,socket).
"""

typeIISymbolSystemInstruction = """Action Blacklist : ["Add","Delete","Set","Match","Merge","Append"]
Data Type Blacklist : ["Function Pointer","Number"]
I have defined a blacklist of actions and a blacklist of data types, and I believe that taint source function names should not contain words with such semantics.For each given function name, you should carefully analyze it and break it down into two semantic components:
1. The action it represents. If the function name implies creating or inserting, match blacklist "Add". If the function name implies removing, match blacklist "Delete". If the function name implies assigning or updating, match blacklist "Set". If the function name implies comparing, match blacklist "Match".
2. The data type it refer. If the function name suggests it deals with function pointer(like handler,pointer), match blacklist "Function Pointer". If the function name suggests it deals with integer or numeric data(like size,int,number), match blacklist "Number".
Only Output all functions matching action blacklist or data type blacklist. You should double check.
Output format: {"function_list":"function1,function2,..."}"""

typeIIImplementSystemInstruction = """Pattern1 Description:For a function parameter in the form of a string, perform a linear character-by-character traversal to search for delimiters in order to split key-value pairs, and sequentially compare the keys of each pair to extract the value of the target field.
Pattern1 Properties:
{"initial_data_source": "function argument",
  "key_matching_strategy": "char-by-char linear scan",
  "value_storage_method": "return || argument"
}
Pattern1 Algorithm
function pattern1(message, key, valueBuffer, lengthLimit)
    pairStart ← strstr(message, key)
    keyLength ← strlen(key)
    valueStart ← pairStart[keyLength]
    if *valueStart != "=" then
        return 1
    else
        pairEnd ← strchr(pairStart, &)
        if pairEnd = 0 then
            valueLength ← strlen(message) + message - pairStart - keyLength
        else
            valueLength ← pairEnd - pairStart - keyLength
        end if
        if lengthLimit < valueLength then
            return 1
        else
            while valueStart != 0 and valueStart != "&" do
                *valueBuffer ← *(valueStart + 1)
                valueBuffer++
                valueStart++
            end while
        return 0
        end if
    end if
end function

Pattern2 Description:For a function parameter in the form of a hash table, use a hash function to locate the bucket where the target field resides, and then sequentially compare the keys within the bucket to extract the value of the target field.
Pattern2 Properties:
{"initial_data_source": "function argument",
  "key_matching_strategy": "bucketed hash scan",
  "value_storage_method": "return || argument"
}
Pattern2 Algorithm
function pattern2(message, key)
    index ← hash(key) mod HASH_T ABLE_SIZE
    entry ← message[index]
    while entry != NULL do
        if *(entry + key_offset) = key then
            return entry + value_offset
        end if
        entry ← entry + next_offset
    end while
    return NULL
end function

Pattern3 Description:For a function parameter in the form of a linked list, perform a linear traversal node by node, sequentially comparing the keys of each node to extract the value of the target field.
Pattern3 Properties:
{"initial_data_source": "function argument",
  "key_matching_strategy": "node-by-node list scan",
  "value_storage_method": "return || argument"
}
Pattern3 Algorithm
function pattern3(message, key)
    currentNode ← message
    while true do
        if currentNode is NULL then
            return NULL
        end if
            if strcmp(currentNode + keyOffset, key) == 0 then
            return currentNode + valueOffset
        end if
        currentNode ← currentNode + nextOffset
    end while
end function

Pattern4 Description:For a global variable in the form of a string, perform a linear character-by-character traversal to search for delimiters in order to split key-value pairs, and sequentially compare the keys of each pair to extract the value of the target field.
Pattern4 Properties:
{"initial_data_source": "global variable",
  "key_matching_strategy": "char-by-char linear scan",
  "value_storage_method": "return || argument"
}
Pattern4 Algorithm
function pattern4(key, valueBuffer, lengthLimit)
    message ← data_xxxxxx
    pairStart ← strstr(message, key)
    keyLength ← strlen(key)
    valueStart ← pairStart[keyLength]
    if *valueStart != "=" then
        return 1
    else
        pairEnd ← strchr(pairStart, &)
        if pairEnd = 0 then
            valueLength ← strlen(message) + message - pairStart - keyLength
        else
            valueLength ← pairEnd - pairStart - keyLength
        end if
        if lengthLimit < valueLength then
            return 1
        else
            while valueStart != 0 and valueStart != "&" do
                *valueBuffer ← *(valueStart + 1)
                valueBuffer++
                valueStart++
            end while
        return 0
        end if
    end if
end function

Pattern5 Description:For a global variable in the form of a hash table, use a hash function to locate the bucket where the target field resides, and then sequentially compare the keys within the bucket to extract the value of the target field.
Pattern5 Properties:
{"initial_data_source": "global variable",
  "key_matching_strategy": "bucketed hash scan",
  "value_storage_method": "return || argument"
}
Pattern5 Algorithm
function pattern5(key)
    message ← data_xxxxxx
    index ← hash(key) mod HASH_T ABLE_SIZE
    entry ← message[index]
    while entry != NULL do
        if *(entry + key_offset) = key then
            return entry + value_offset
        end if
        entry ← entry + next_offset
    end while
    return NULL
end function

Pattern6 Description:For a global variable in the form of a linked list, perform a linear traversal node by node, sequentially comparing the keys of each node to extract the value of the target field.
Pattern6 Properties:
{"initial_data_source": "global variable",
  "key_matching_strategy": "node-by-node list scan",
  "value_storage_method": "return || argument"
}
Pattern6 Algorithm
function pattern6(key)
    currentNode ← data_xxxxxx
    while true do
        if currentNode is NULL then
            return NULL
        end if
            if strcmp(currentNode + keyOffset, key) == 0 then
            return currentNode + valueOffset
        end if
        currentNode ← currentNode + nextOffset
    end while
end function

Pattern7 Description:For a character device (such as NVRAM), use a system call to send a query command for the specified field to the driver, and extract the value of the target field.
Pattern7 Properties:
{"initial_data_source": "character device",
    "key_matching_strategy": "driver ioctl lookup",
    "value_storage_method": "return || argument"
}
Pattern7 Algorithm
function pattern7(key)
    device_ioctl_command
    device_fd ← open(DEVICE_DEVICE, O_RDWR)
    strcpy(device_ioctl_command + key_offset, key)
    ioctl(device_fd, DEVICE_IOCTL_GET, &device_ioctl_command)
    if device_ioctl_command + value_offset != 0 then
        return device_ioctl_command + value_offset
    else
        return 0
    end if
end function

Pattern8 Description:For a regular file, perform a linear character-by-character traversal to locate delimiters for splitting key-value pairs, and sequentially compare the keys to extract the value of the target field.
{"initial_data_source": "regular file in text stream form",
  "key_matching_strategy": "char-by-char linear scan",
  "value_storage_method": "return || argument"
}
Pattern8 Algorithm
function Pattern8(key, valueBuffer, lengthLimit)
    fp ← fopen(REGULAR_FILE, "r")
    fgets(message, sizeof(message), fp)
    pairStart ← strstr(message, key)
    keyLength ← strlen(key)
    valueStart ← pairStart[keyLength]
    if *valueStart != "=" then
        return 1
    else
        pairEnd ← strchr(pairStart, &)
        if pairEnd = 0 then
            valueLength ← strlen(message) + message - pairStart - keyLength
        else
            valueLength ← pairEnd - pairStart - keyLength
        end if
        if lengthLimit < valueLength then
            return 1
        else
            while valueStart != 0 and valueStart != "&" do
                *valueBuffer ← *(valueStart + 1)
                valueBuffer++
                valueStart++
            end while
        return 0
        end if
    end if
end function

Pattern9 Description:For a regular file, first map it into the process virtual address space, then perform a linear character-by-character traversal, sequentially comparing the keys to extract the value of the target field.
Pattern9 Properties:
{"initial_data_source": "regular file in memory map form",
    "key_matching_strategy": "char-by-char linear scan",
    "value_storage_method": "return || argument"
}
Pattern9 Algorithm
function Pattern9(key, valueBuffer, lengthLimit)
    fd ← open(REGULAR_FILE, O_RDONLY)
    message ← mmap(NULL, MEMORY_SIZE, PROT_READ, MAP_SHARED, fd, 0)
    pairStart ← strstr(message, key)
    keyLength ← strlen(key)
    valueStart ← pairStart[keyLength]
    if *valueStart != "=" then
        return 1
    else
        pairEnd ← strchr(pairStart, &)
        if pairEnd = 0 then
            valueLength ← strlen(message) + message - pairStart - keyLength
        else
            valueLength ← pairEnd - pairStart - keyLength
        end if
        if lengthLimit < valueLength then
            return 1
        else
            while valueStart != 0 and valueStart != "&" do
                *valueBuffer ← *(valueStart + 1)
                valueBuffer++
                valueStart++
            end while
        return 0
        end if
    end if
end function

You are a professional static analysis expert.
Your task is to analyze a BATCH of decompiled C functions (represented in HLIL) and determine whether their logic matches 9 known field extraction patterns (definitions provided separately) or acts as a "Wrapper Source".

[INPUT FORMAT]
The input provided contains MULTIPLE functions to be analyzed in a batch. 
Each entry is separated by "-----------------------------------".
Structure of a single entry:
1. === TARGET FUNCTION: [FunctionName] ===
   (The function you must classify. If this function contains metadata like "[METADATA] TYPE: DYNAMIC IMPORT", follow the instruction strictly.)
2. === REFERENCE CONTEXT === (Optional)
   (Source code of inner functions provided for context. Use them to understand the data flow.)

[OUTPUT FORMAT]
Output a SINGLE JSON object containing results for ALL Target Functions in the batch.
Keys are function names, and values must follow the strict format below:
{"Function_Name1": "Return_Value_Type", "Function_Name2": "Return_Value_Type", ...}

The "Return_Value_Type" must be ONE of the following four types. You must evaluate them in the order listed.

--- TYPE 1: Uncertain (Context Request) ---
Format: "Uncertain||sub_xxxx||sub_yyyy"
**CRITICAL RULE**: You **MUST** return this type if the logic depends on an inner function named starting with 'sub_' (e.g., 'sub_12345') AND its code is NOT provided in the Reference section.
**METADATA OVERRIDE (HIGHEST PRIORITY)**: 
If the Target Function code contains the tag `// [METADATA] TYPE: DYNAMIC IMPORT FUNCTION...`, you are **STRICTLY FORBIDDEN** from returning Uncertain AND you should return **Type 1 (Pattern ID)** OR **TYPE 3 (True)** OR **TYPE 4 (None)**.
**Trigger Conditions** (Evaluate these ONLY if the Metadata Override does NOT apply):
1. **Direct Return Dependency**: The code matches `return sub_xxxx(...);` or `res = sub_xxxx(...); return res;` and `sub_xxxx` is unknown.
2. **Output Parameter Dependency**: The code writes the result of `sub_xxxx` into a pointer argument, and `sub_xxxx` is unknown.
3. **Unknown Internal Logic**: During analysis, if you encounter ANY unknown function (stripped or external) and you need to know its internal logic/semantics to determine the taint propagation, you **MUST** return Uncertain to request it.
**Constraint**: List at most 2 most critical `sub_` functions.

--- TYPE 2: Pattern ID ---
Format: "1" ~ "9"
Return the specific Pattern ID if the function's logic strictly matches one of the 9 known field extraction patterns provided in your knowledge base.

--- TYPE 3: True (Wrapper Source) ---
Format: "True"
Return True if and only if the function acts as a wrapper for a **KNOWN** taint source. This requires satisfying BOTH conditions:
1. **Invocation**: The function calls a **CONFIRMED** data extraction function. This includes:
    - Functions with explicit meaningful names implying retrieval (e.g., 'nvram_get', 'websGetVar', 'cJSON_Parse').
    - `sub_` functions whose code is provided in the "REFERENCE CONTEXT" section and you have analyzed them to be sources.
2. **Propagation**: Semantic data-flow analysis confirms the retrieved data is successfully propagated out via **Return Value** or **Output Parameter**.
**CONDITIONAL EXCLUSION (Trusted Sources - High Confidence Only)**: 
You may return **Type 4 (None)** ONLY if you are **ABSOLUTELY CERTAIN** the data source is **immutable hardware state** or **uncontrollable system info** (e.g., `get_cpu_temp`, `get_uptime`, `get_kernel_version`, `getMac`, `getIP`).
**SAFETY NET (Recall Priority)**: 
- If there is **ANY ambiguity** whether the data might be derived from configuration, NVRAM, or network , **DO NOT EXCLUDE**. Treat it as a Valid Taint Source (True).
- **Principle**: Better to include a trusted source (False Positive) than to miss a real taint source (False Negative).
**ANTI-HALLUCINATION RULE**: 
- If the function calls `sub_unknown(...)` and propagates its result, but you don't have the code for `sub_unknown`, you **MUST** return **Type 1 (Uncertain)**, NOT True.

--- TYPE 4: None ---
Format: "None"
Return None if the function does not match any Pattern, is not a Wrapper Source, or only uses retrieved data for internal logic (e.g., comparison) without propagating it out.
"""



def clac_tokens():
    print(colored("Token counting is skipped as it requires Google native API.", "yellow"))
    pass



def generate(sysInstruction, uInstruction):
    config = get_llm_config("source")
    client = OpenAI(
        api_key=config["api_key"],
        base_url=config["base_url"],
    )

    messages = [
        {"role": "system", "content": sysInstruction},
        {"role": "user", "content": uInstruction}
    ]

    try:
        response_stream = client.chat.completions.create(
            model=config["model"],
            messages=messages,
            temperature=0,
            top_p=0.95,
            response_format={"type": "json_object"},
            stream=True,
        )

        final_response = ""

        for chunk in response_stream:
            if chunk.choices[0].delta.content is not None:
                final_response += chunk.choices[0].delta.content
        
        final_response = final_response.strip()
        if final_response.startswith("```json"):
            final_response = final_response[7:]
        if final_response.startswith("```"):
            final_response = final_response[3:]
        if final_response.endswith("```"):
            final_response = final_response[:-3]

        return final_response

    except Exception as e:
        print(colored(f"API Error: {str(e)}", "red"))
        return "{}"

SOURCE_WRITE_FUNCS: Set[str] = {
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strlcpy", "strcat", "strncat",
    "sprintf", "snprintf", "vsprintf", "vsnprintf" 
}

SET_VAR_OPS = {MediumLevelILOperation.MLIL_SET_VAR_SSA, MediumLevelILOperation.MLIL_SET_VAR, MediumLevelILOperation.MLIL_VAR_PHI}


def _to_var(v: Union[Variable, SSAVariable]) -> Variable:  # noqa: D401
    """Return core `Variable` regardless of SSA wrapper."""
    return v.var if isinstance(v, SSAVariable) else v


def _vars_read(i: MediumLevelILInstruction) -> Set[Variable]:
    return {_to_var(v) for v in i.vars_read}

def _vars_written(i: MediumLevelILInstruction) -> Set[Variable]:
    return {_to_var(v) for v in i.vars_written}


def _extract_called_name(bv, instr: MediumLevelILInstruction) -> str | None:
    if instr.operation not in {
        MediumLevelILOperation.MLIL_CALL_SSA,
        MediumLevelILOperation.MLIL_TAILCALL_SSA,
    }:
        return None
    dest = instr.dest
    if isinstance(dest, MediumLevelILImport):
        callee = bv.get_symbol_at(dest.constant)
        if callee:
            return callee.name
    elif isinstance(dest, binaryninja.MediumLevelILConstPtr):
        f = bv.get_function_at(dest.constant)
        if f:
            return f.name
        sym = bv.get_symbol_at(dest.constant)
        if sym:
            return sym.name
    return None


def _extract_vars(expr: MediumLevelILInstruction) -> Set[Variable]:
    out: Set[Variable] = set()
    if expr.operation in {
        MediumLevelILOperation.MLIL_VAR_SSA, 
        MediumLevelILOperation.MLIL_VAR, 
        MediumLevelILOperation.MLIL_ADDRESS_OF
    }:
        out.add(_to_var(expr.src))
    for op in expr.operands:
        if isinstance(op, MediumLevelILInstruction):
            out.update(_extract_vars(op))
    return out


def _get_usages(f: Function, v: Variable) -> List[MediumLevelILInstruction]:
    return [i for b in f.mlil.ssa_form for i in b if v in _vars_read(i)]



def _is_write_op(bv, i: MediumLevelILInstruction, v: Variable) -> bool:
    op = i.operation
    if op == MediumLevelILOperation.MLIL_STORE_SSA and v in _extract_vars(i.dest):
        return True
    if op in {MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA}:
        name = _extract_called_name(bv, i)
        if name in SOURCE_WRITE_FUNCS and len(i.params) >= 1:
            return v in _extract_vars(i.params[0])
    return False

def _alias_vars(i: MediumLevelILInstruction, v: Variable) -> Set[Variable]:
    if i.operation in SET_VAR_OPS and v in _vars_read(i):
        return _vars_written(i)
    return set()


def identify_source_parameters(bv, f: Function) -> Set[Variable]:
    """Track each parameter independently and report the original tainted inputs."""
    sources: Set[Variable] = set()
    for param in f.parameter_vars:
        worklist: List[Variable] = [param]
        visited: Set[Variable] = set()
        is_source_param = False
        while worklist:
            cur = worklist.pop()
            if cur in visited:
                continue
            visited.add(cur)
            usages = _get_usages(f, cur)
            for u in usages:
                if _is_write_op(bv, u, cur):
                    is_source_param = True
                    break
                if not is_source_param:
                    for alias in _alias_vars(u, cur):
                        if alias not in visited:
                            worklist.append(alias)
            if is_source_param:
                break
        if is_source_param:
            sources.add(param)
    return sources

def _parse_addr(s: str) -> int:
    return int(s, 16) if s.lower().startswith("0x") else int(s)

def _resolve_func(bv, ident: str) -> Function | None:
    if ident.lower().startswith("0x") or ident.isdigit():
        return bv.get_function_at(_parse_addr(ident))
    func = bv.get_functions_by_name(ident)
    if func:
        return bv.get_function_at(func[0].start)
    return None

def get_symbols_list(bv):
    symbol_list = []
    for symbol in bv.get_symbols():
        symbol_list.append(symbol.name)
    return symbol_list

SUPPORTED_ARCHS = {
    "armv7":  {"args": {"r0", "r1", "r2", "r3"}},
    "thumb2": {"args": {"r0", "r1", "r2", "r3"}},
    "mips32": {"args": {"a0", "a1", "a2", "a3"}},
    "mipsel32": {"args": {"a0", "a1", "a2", "a3"}},
    "aarch64": {"args": {"x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"}}
}

def _get_first_dest_reg(inst):
    """Return the first destination register in a disassembly instruction."""
    for token in inst.tokens:
        if token.type == InstructionTextTokenType.RegisterToken:
            return token.text.lower()
    return None


def _get_src_regs(inst):
    """Return all source registers after the first destination register."""
    srcs = set()
    found_dest = False
    for token in inst.tokens:
        if token.type == InstructionTextTokenType.RegisterToken:
            if not found_dest:
                found_dest = True
                continue
            srcs.add(token.text.lower())
    return srcs



def _extract_callee_name_asm(bv, inst):
    """Extract a callee name from a disassembly call instruction."""
    for token in inst.tokens:
        if token.type in {
            binaryninja.InstructionTextTokenType.CodeSymbolToken,
            binaryninja.InstructionTextTokenType.ImportToken,
        }:
            return token.text.strip()

        if token.type in {binaryninja.InstructionTextTokenType.CodeRelativeAddressToken, 
                          binaryninja.InstructionTextTokenType.PossibleAddressToken,
                          binaryninja.InstructionTextTokenType.IntegerToken}:
            try:
                addr = token.value
                sym = bv.get_symbol_at(addr)
                if sym:
                    return sym.name
                f = bv.get_function_at(addr)
                if f:
                    return f.name
            except:
                pass

        if token.type == binaryninja.InstructionTextTokenType.TextToken:
            text = token.text.strip()
            if text and (text.startswith("sub_") or text[0].isalpha()):
                funcs = bv.get_functions_by_name(text)
                if funcs:
                    return funcs[0].name
                    
    return None

def _get_instruction_mnemonic(inst):
    """Return the instruction mnemonic without address prefixes."""
    for token in inst.tokens:
        if token.type == binaryninja.InstructionTextTokenType.InstructionToken:
            return token.text.upper()
    return ""

def get_init_functions(bv):
    """Collect candidate source-like functions referenced by string constants."""
    arch_name = bv.arch.name
    if arch_name not in SUPPORTED_ARCHS:
        print(colored(f"[!] Error: Unsupported Architecture '{arch_name}'. Only ARM/MIPS allowed.", "red"))
        return []
    
    ARG_REGS = SUPPORTED_ARCHS[arch_name]["args"]

    variable_pattern = re.compile(r"^[a-zA-Z]\w+$")
    if bv.get_section_by_name(".rodata") != None:
        rodata = bv.get_section_by_name(".rodata")
        strings = bv.get_strings(rodata.start, rodata.length)
    else:
        strings = bv.strings

    ref_function_name_dict = {}

    for string in strings:
        if not variable_pattern.match(string.value):
            continue

        refs = bv.get_code_refs(string.start)
        for ref in refs:
            function_name = None
            if ref.mlil is None:
                continue

            if isinstance(ref.mlil, binaryninja.mediumlevelil.MediumLevelILCall):
                if isinstance(ref.mlil.dest, binaryninja.mediumlevelil.MediumLevelILImport):
                    function_name = bv.get_symbol_at(ref.mlil.dest.constant).name
                elif isinstance(ref.mlil.dest, binaryninja.mediumlevelil.MediumLevelILConstPtr):
                    function_name = bv.get_function_at(ref.mlil.dest.constant).name
                elif isinstance(ref.mlil.dest, binaryninja.mediumlevelil.MediumLevelILVar):
                    pass
                else:
                    pass

            elif isinstance(ref.mlil, binaryninja.mediumlevelil.MediumLevelILSetVar):
                func = ref.function
                if not func:
                    continue

                block = func.get_basic_block_at(ref.address)
                if not block:
                    continue

                instructions = block.disassembly_text
                start_instr_index = -1
                for idx, inst in enumerate(instructions):
                    if inst.address == ref.address:
                        start_instr_index = idx
                        break
                
                if start_instr_index == -1:
                    continue

                init_inst = instructions[start_instr_index]
                tracked_regs = set()
                first_reg = _get_first_dest_reg(init_inst)
                
                if first_reg:
                    tracked_regs.add(first_reg)

                if not tracked_regs:
                    continue

                SCAN_WINDOW = 12
                curr_idx = start_instr_index + 1
                
                for _ in range(SCAN_WINDOW):
                    if curr_idx >= len(instructions):
                        break
                    inst = instructions[curr_idx]
                    curr_idx += 1
                    
                    mnemonic = _get_instruction_mnemonic(inst)

                    if mnemonic.startswith("BL") or mnemonic.startswith("JAL") or mnemonic.startswith("B "):
                        intersection = tracked_regs.intersection(ARG_REGS)
                        if intersection:
                            callee_name = _extract_callee_name_asm(bv, inst)
                            if callee_name:
                                function_name = callee_name
                                break
                    
                    dest_reg = _get_first_dest_reg(inst)
                    if dest_reg:
                        src_regs = _get_src_regs(inst)
                        if not tracked_regs.isdisjoint(src_regs):
                            tracked_regs.add(dest_reg)
                        elif dest_reg in tracked_regs:
                            tracked_regs.discard(dest_reg)
                            if not tracked_regs:
                                break

            if function_name is None:
                continue
            elif function_name in ref_function_name_dict:
                ref_function_name_dict[function_name] += 1
            else:
                ref_function_name_dict[function_name] = 1

    sorted_ref_function_name_items = sorted(ref_function_name_dict.items(), key=lambda x: x[1], reverse=True)
    return sorted_ref_function_name_items




def visitor(_a, inst, _c, _d):
    if _a != "root":
        print(_a, inst, _c, _d.expr_type)
    else:
        print(_a, inst, _c)

def print_str_refs(str_address):
    refs = bv.get_code_refs(str_address)
    for ref in refs:
        if ref.hlil:
            print(ref.hlil.ssa_form)
            ref.hlil.visit(visitor)
            print("-----------------------------------------")

def handle_indirect(functions):
    result = set()
    for function in functions:
        if "getenv" in function.lower():
            result.add(function)
        if "nvram" in function.lower() and "get" in function.lower():
            result.add(function)
    return result

def get_var_uses(func_addr, arg_name):
    func = bv.get_function_at(func_addr)
    var = func.get_variable_by_name(arg_name)
    for use in func.mlil.get_var_uses(var):
        if isinstance(use, binaryninja.mediumlevelil.MediumLevelILSetVar):
            print(use.detailed_operands)
            print("vars_written:", use.vars_written)
            print("vars_read:", use.vars_read)
        else:
            print(use)
            print(type(use))
def is_dll(file):
    if not os.path.exists(file):
        return False
    if os.path.islink(file):
        target = os.readlink(file)
        if not os.path.isabs(target):
            link_dir = os.path.dirname(os.path.abspath(file))
            target_path = os.path.normpath(os.path.join(link_dir, target))
        return is_dll(target_path)
    mime = magic.Magic(mime=True)
    mime_type = mime.from_file(file)
    return mime_type == "application/x-sharedlib"


def check_function_defined(elf_file_path, target_function_name):
    if not os.path.exists(elf_file_path):
        return False
    with open(elf_file_path, 'rb') as file:
        elf_file = ELFFile(file)
        for section in elf_file.iter_sections():
            if section.name == '.dynsym':
                symbol = section.get_symbol_by_name(target_function_name)
                if symbol:
                    for i, section in enumerate(elf_file.iter_sections()):
                        if section.name == '.text':
                            if symbol[0].entry.st_shndx == i:
                                return elf_file_path
    return False

def is_elf_file(filepath):
    """Return True when the path points to an ELF binary."""
    try:
        if not os.path.isfile(filepath):
            return False
        with open(filepath, "rb") as file_obj:
            return file_obj.read(4) == b"\x7fELF"
    except Exception:
        return False

def read_fake_link_content(filepath):
    """Read a small text pseudo-link file and return its target path."""
    try:
        if os.path.getsize(filepath) > 512:
            return None
        with open(filepath, "rb") as file_obj:
            content = file_obj.read()
            if content.startswith(b'\x7fELF'):
                return None
            try:
                return content.decode("utf-8").strip()
            except UnicodeDecodeError:
                return None
    except Exception:
        return None

def find_so_files(root_dir, libraries_list):
    """Resolve shared libraries, including text pseudo-links."""
    so_files = []
    libs_needed = set(libraries_list)
    
    print(colored(f"[*] Scanning {root_dir} for libraries (Smart Link Resolve)...", "blue"))

    file_map = {}
    
    print(colored("    -> Building file index...", "cyan"))
    for dirpath, _, filenames in os.walk(root_dir):
        for filename in filenames:
            if filename not in file_map:
                file_map[filename] = []
            file_map[filename].append(os.path.join(dirpath, filename))

    for lib_name in libs_needed:
        if lib_name not in file_map:
            continue
        candidates = file_map[lib_name] 
        for candidate_path in candidates:
            if is_elf_file(candidate_path):
                so_files.append(candidate_path)
            else:
                target_name_or_path = read_fake_link_content(candidate_path)
                if target_name_or_path:
                    target_filename = os.path.basename(target_name_or_path)
                    
                    if target_filename in file_map:
                        real_candidates = file_map[target_filename]
                        found_real = False
                        for real_path in real_candidates:
                            if is_elf_file(real_path):
                                print(colored(f"    [Resolve] {lib_name} (Text) -> {target_filename} (ELF)", "green"))
                                so_files.append(real_path)
                                found_real = True
                        if not found_real:
                            print(colored(f"    [Fail] {lib_name} -> points to {target_filename}, but it's not a valid ELF.", "red"))
                    else:
                        print(colored(f"    [Fail] {lib_name} -> points to {target_filename}, but file not found.", "red"))

    unique_so_files = list(set(so_files))
    return unique_so_files


def find_function_defined_in_which_so_file(function_name,root_dir,libraries_list):
    all_so_files = find_so_files(root_dir,libraries_list)
    for so in all_so_files:
        if is_dll(so):
            result = check_function_defined(so, function_name)
            if result != False:
                return result
    return False

def get_function_sourcecode_in_HLIL(bv, function_name):
    """Return HLIL text when available and fall back to None on failure."""
    current_function = None
    funcs = bv.get_functions_by_name(function_name)
    if funcs:
        current_function = funcs[0]
    if not current_function:
        print(colored(f"[!]        Fail to find {function_name}!", "red"))
        return None    
    try:
        if current_function.hlil:
            return '\n'.join(map(str, current_function.hlil.root.lines))
    except Exception as e:
        print(colored(f"[!] Error generating HLIL for {function_name}: {e}", "red"))
    return None

def get_function_sourcecode_in_assembly_language(bv,function_name):
    current_function = bv.get_functions_by_name(function_name)[0]
    disassembly_code = ""
    for block in current_function:
        for instruction in block.disassembly_text:
            disassembly_code += hex(instruction.address) + "\t" + str(instruction) + "\n"
    return disassembly_code

def get_all_imported_functions(bv,function_name):
    imported_symbols = bv.get_symbols_of_type(binaryninja.SymbolType.ImportedFunctionSymbol)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} path_to_binary path_to_firmware_root")
        sys.exit(1)

    bndb_path = sys.argv[1]
    root_dir = sys.argv[2]

    print(colored(f"[*] [Phase 1] Loading binary: {bndb_path} ...", "cyan"))
    bv = binaryninja.load(bndb_path)

    print(colored(f"[*] [Phase 1] Scanning .rodata for string references (Heuristic Detection)...", "cyan"))
    rodata_string_ref_functions = get_init_functions(bv)
    print(colored(f"[+] Found {len(rodata_string_ref_functions)} candidate functions referencing strings.", "green"))

    print(colored(f"[*] [Phase 2] Classifying candidates into Static/Dynamic...", "cyan"))
    candidate_source_function_static = {}
    candidate_source_function_dynamic = {}
    func_so_info = {}

    func_so_info[bndb_path] = set()
    for i in rodata_string_ref_functions:
        function_name = i[0]
        is_dynamic = True
        current_function = bv.get_functions_by_name(function_name)
        for func in current_function:
            if func.symbol.type == binaryninja.SymbolType.FunctionSymbol:
                is_dynamic = False
                func_so_info[bndb_path].add(function_name)
                if function_name in candidate_source_function_static:
                    continue
                candidate_source_function_static[function_name] = ""
                current_function = current_function[0]
                candidate_source_function_static[function_name] += str(function_name) + str(current_function.parameter_vars.vars) + "\n"
                candidate_source_function_static[function_name] += get_function_sourcecode_in_HLIL(bv,function_name)
        if is_dynamic:
            candidate_source_function_dynamic[function_name] = ""

    print(colored(f"[+] Static candidates: {len(candidate_source_function_static)}", "green"))
    print(colored(f"[+] Dynamic candidates (need resolution): {len(candidate_source_function_dynamic)}", "green"))

    print(colored(f"[*] [Phase 3] Identifying Type I Sources via LLM...", "cyan"))
    imported_symbols = bv.get_symbols_of_type(binaryninja.SymbolType.ImportedFunctionSymbol)
    imported_function_names = [sym.name for sym in imported_symbols]

    candidate_typeI_functions = list(set(imported_function_names) - set(candidate_source_function_dynamic.keys()))

    print(colored(f"[*] Sending {len(candidate_typeI_functions)} imported functions to LLM for Type I check...", "yellow"))
    userInstruction = str(candidate_typeI_functions)
    typeI_source_identification_result = json.loads(generate(typeIsystemInstruction, userInstruction))
    print(colored(f"[+] Type I Identification complete.", "green"))

    print(colored(f"[*] [Phase 4] Filtering Type II candidates by Name/Symbol via LLM...", "cyan"))
    all_candidates = set(candidate_source_function_dynamic.keys()).union(set(candidate_source_function_static.keys()))
    candidates_to_check = {
        func for func in all_candidates
        if not (func.startswith("sub") or func.startswith("j_sub"))
    }
    userInstruction = str(candidates_to_check)
    print(colored(f"[*] Total candidates: {len(all_candidates)}. Sending {len(candidates_to_check)} named functions to blacklist check...", "yellow"))
    typeIISymbolResponse = json.loads(generate(typeIISymbolSystemInstruction, userInstruction))['function_list'].split(',')

    original_dynamic_count = len(candidate_source_function_dynamic)
    original_static_count = len(candidate_source_function_static)

    candidate_source_function_dynamic = {k: v for k, v in candidate_source_function_dynamic.items() if k not in typeIISymbolResponse}
    candidate_source_function_static = {k: v for k, v in candidate_source_function_static.items() if k not in typeIISymbolResponse}

    print(colored(f"[+] Filtered out {len(typeIISymbolResponse)} functions.", "green"))
    print(colored(f"    Dynamic: {original_dynamic_count} -> {len(candidate_source_function_dynamic)}", "green"))
    print(colored(f"    Static:  {original_static_count} -> {len(candidate_source_function_static)}", "green"))

    print(colored(f"[*] [Phase 5] Resolving Dynamic functions in {root_dir}...", "cyan"))
    excluded_prefixes = ("libc.so", "libpthread.so", "libgcc")
    libraries_list = [lib for lib in bv.libraries if not lib.startswith(excluded_prefixes)]
    bv.file.close()

    libraries_path_list = find_so_files(root_dir, libraries_list)
    print(colored(f"[*] Found {len(libraries_path_list)} potential shared objects.", "yellow"))

    for so_file in libraries_path_list:
        func_so_info[so_file] = set()
        bv = binaryninja.load(so_file)
        for function_name in candidate_source_function_dynamic:
            current_function = bv.get_functions_by_name(function_name)
            for i in current_function:
                if i.symbol.type == binaryninja.SymbolType.FunctionSymbol:
                    func_so_info[so_file].add(function_name)
                    current_function = current_function[0]
                    candidate_source_function_dynamic[function_name] += function_name + str(current_function.parameter_vars.vars) + "\n"
                    candidate_source_function_dynamic[function_name] += get_function_sourcecode_in_HLIL(bv, function_name)

        bv.file.close()

    print(colored(f"[*] [Phase 6] Analyzing Logic Patterns via LLM (Batch Iteration)...", "cyan"))

    pending_funcs = list(candidate_source_function_static.keys()) + list(candidate_source_function_dynamic.keys())

    context_map = {fname: {} for fname in pending_funcs}
    final_results = {}
    reference_cache = LRUCache(15)

    MAX_ROUNDS = 4
    MAX_CONTEXT_LIMIT = 4

    for round_idx in range(1, MAX_ROUNDS + 1):
        if not pending_funcs:
            print(colored("[*] No more functions to analyze. Stopping.", "green"))
            break

        print(colored(f"[*] Batch Round {round_idx}/{MAX_ROUNDS}: Analyzing {len(pending_funcs)} functions...", "yellow"))

        userInstruction = ""

        if round_idx == MAX_ROUNDS:
            userInstruction += "!!! FINAL ROUND WARNING: This is the LAST chance. You MUST provide a definitive answer. DO NOT return Uncertain. !!!\n\n"

        for fname in pending_funcs:
            is_dynamic = fname in candidate_source_function_dynamic

            if is_dynamic:
                code = candidate_source_function_dynamic[fname]
            else:
                code = candidate_source_function_static[fname]

            userInstruction += f"=== TARGET FUNCTION: {fname} ===\n"

            if is_dynamic:
                userInstruction += "// [METADATA] TYPE: DYNAMIC IMPORT FUNCTION. You MUST provide a definitive answer. DO NOT return Uncertain. !!! \n"

            userInstruction += f"{code}\n"

            refs = context_map.get(fname, {})
            if refs:
                userInstruction += "=== REFERENCE CONTEXT ===\n"
                for ref_name, ref_code in refs.items():
                    userInstruction += f"--- Function: {ref_name} ---\n{ref_code}\n"

            userInstruction += "\n-----------------------------------\n"

        try:
            response_text = generate(typeIIImplementSystemInstruction, userInstruction)
            batch_response = json.loads(response_text)
        except Exception as e:
            print(colored(f"[-] Batch API Error in Round {round_idx}: {e}", "red"))
            batch_response = {}

        next_round_funcs = []
        functions_needing_context = {}

        for fname in pending_funcs:
            is_dynamic = fname in candidate_source_function_dynamic

            if fname not in batch_response:
                if round_idx < MAX_ROUNDS:
                    print(colored(f"    [!] LLM missed function: {fname}, retrying next round", "yellow"))
                    next_round_funcs.append(fname)
                else:
                    print(colored(f"    [!] LLM missed function: {fname} in Final Round, defaulting to None", "red"))
                    final_results[fname] = "None"
                continue

            result = str(batch_response[fname])

            if result.startswith("Uncertain"):
                if is_dynamic:
                    print(colored(f"    [-] {fname} (Dynamic) returned Uncertain -> retrying next round", "yellow"))
                    next_round_funcs.append(fname)
                    continue

                if round_idx == MAX_ROUNDS:
                    print(colored(f"    [-] {fname} (Final Round) returned Uncertain -> Forced None", "red"))
                    final_results[fname] = "None"
                    continue

                parts = result.split("||")
                wanted_funcs = [x.strip() for x in parts[1:] if x.strip()]

                if wanted_funcs:
                    functions_needing_context[fname] = wanted_funcs
                    next_round_funcs.append(fname)
                else:
                    final_results[fname] = "None"
            else:
                print(colored(f"    [+] {fname} -> {result}", "green"))
                final_results[fname] = result

        if next_round_funcs and functions_needing_context:
            print(colored(f"[*] Post-Batch: Reloading Binary to fetch context...", "blue"))

            if 'bv' in locals() and bv:
                bv.file.close()
            bv = binaryninja.load(bndb_path)

            for target, wanted_list in functions_needing_context.items():
                if len(context_map[target]) >= MAX_CONTEXT_LIMIT:
                    continue

                for wf in wanted_list:
                    if wf in context_map[target]:
                        continue

                    cached_code = reference_cache.get(wf)
                    if cached_code:
                        context_map[target][wf] = cached_code
                        print(colored(f"        [Cache Hit] {wf} for {target}", "green"))
                    else:
                        wf_code = get_function_sourcecode_in_HLIL(bv, wf)
                        if wf_code:
                            context_map[target][wf] = wf_code
                            reference_cache.put(wf, wf_code)
                            print(colored(f"        [Loaded] {wf} for {target}", "green"))
                        else:
                            context_map[target][wf] = "// [Error] Function body not found."
                            print(colored(f"        [Missing] {wf} for {target}", "red"))

        pending_funcs = next_round_funcs

    print(colored(f"[*] [Phase 6 Complete] Processing final results...", "cyan"))

    if 'bv' not in locals() or bv is None:
        bv = binaryninja.load(bndb_path)
    elif bv.file.filename != bndb_path:
        bv.file.close()
        bv = binaryninja.load(bndb_path)

    typeIISourceFunc = set()
    for func, res in final_results.items():
        if res != "None":
            typeIISourceFunc.add(func)

    all_candidates_keys = set(candidate_source_function_static.keys()).union(set(candidate_source_function_dynamic.keys()))
    typeIISourceFunc = typeIISourceFunc.union(handle_indirect(all_candidates_keys))

    typeIISource = {}

    for so in func_so_info:
        bv = binaryninja.load(so)
        for func in func_so_info[so]:
            if func in typeIISourceFunc:
                current_function = _resolve_func(bv, func)
                params = identify_source_parameters(bv, current_function)
                order = {v: i + 1 for i, v in enumerate(current_function.parameter_vars)}
                idxs = sorted(order[p] for p in params if p in order)
                if idxs:
                    typeIISource[func] = idxs[0] if len(idxs) == 1 else idxs
                else:
                    typeIISource[func] = "Return"

    missed_funcs = typeIISourceFunc - set(typeIISource.keys())

    if missed_funcs:
        print(colored(f"[*] Catch-all triggered: {len(missed_funcs)} functions missed parameter analysis. Defaulting to 'Return'.", "yellow"))
        for func in missed_funcs:
            typeIISource[func] = "Return"
            print(colored(f"    [Fallback] {func} -> Return", "green"))

    print(colored("typeI_source_identification_result", "red"), typeI_source_identification_result)
    print(colored("typeIISource", "red"), typeIISource)
    
