import ast
import re
import binaryninja
import os
import json
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Set, Union
from binaryninja import (
    Function,
    MediumLevelILInstruction,
    MediumLevelILOperation,
    MediumLevelILImport,
    Variable,
    SSAVariable,
    load
)
from openai import OpenAI
from termcolor import colored

API_CONFIG_PATH = Path(__file__).with_name("api_config.json")
_API_CONFIG_CACHE: Dict[str, Any] | None = None

systemInstruction_Template = """
To avoid buffer overflow vulnerabilities, developers usually adopt the following approaches:
1. Always perform boundary checks on all input data to ensure the input does not exceed the predefined buffer size.
2. Avoid using functions that are prone to causing buffer overflows, such as using fgets instead of gets, strncpy instead of strcpy, and snprintf instead of sprintf.
To avoid command execution vulnerabilities, developers usually adopt the following approaches:
1. Use whitelist validation to ensure that the input matches the expected content, restricting allowed characters, formats, or ranges.
2. Use blacklist validation for user input, explicitly prohibiting potentially malicious characters, patterns, or behaviors.
For each provided function implementation, perform a data-flow analysis to identify which parameter is propagated to a dangerous sink. Dangerous sinks belong to two categories:
1. command injection: system, execv, popen, execve, execl, execle, execlp, execvp, fexecve
2. buffer overflow: strcat, strncat, strcpy, strncpy, memcpy, memmove, sprintf, snprintf, sscanf, scanf, gets

Input Format:
Each function block is separated by ---------------------------------------- and contains:
Function Name: <function name>
Dangerous Standard Calls:
- <callee name> [command injection]
- <callee name> [buffer overflow]
HLIL:
<function signature and HLIL>

Use the listed dangerous standard calls as hints about which sinks appear in the function, but confirm the vulnerable parameter by analyzing the HLIL semantics. Return None if no function parameter is propagated to a dangerous sink in a vulnerable way.
The output format is {"function1": "argument number || None", "function2": "argument number || None"}, where each key is the function name from Function Name and the corresponding value indicates the 1-based vulnerable argument number (for example 1,2,3,4) or None if no vulnerability is found.
"""
LLM_BATCH_SIZE = 20
MAX_LLM_FAILURES = 3
CMI_FUNCS: Set[str] = {
    "system",
    "execv",
    "popen",
    "execve",
    "execl",
    "execle",
    "execlp",
    "execvp",
    "fexecve",
}
BOF_FUNCS: Set[str] = {
    "strcat",
    "strncat",
    "strcpy",
    "strncpy",
    "memcpy",
    "memmove",
    "sprintf",
    "snprintf",
    "sscanf",
    "scanf",
    "gets",
}

# Select which dangerous sink categories are enabled globally.
# - "all": enable both CMI_FUNCS and BOF_FUNCS
# - "cmi": enable only CMI_FUNCS
# - "bof": enable only BOF_FUNCS
DANGER_FUNC_MODE = "all"


def build_selected_danger_func_types(mode: str) -> Dict[str, str]:
    normalized_mode = mode.strip().lower()
    if normalized_mode in {"all", "both", "cmi+bof", "bof+cmi"}:
        return {
            **{name: "command injection" for name in CMI_FUNCS},
            **{name: "buffer overflow" for name in BOF_FUNCS},
        }
    if normalized_mode == "cmi":
        return {name: "command injection" for name in CMI_FUNCS}
    if normalized_mode == "bof":
        return {name: "buffer overflow" for name in BOF_FUNCS}
    raise ValueError(
        f"Unsupported DANGER_FUNC_MODE={mode!r}, expected one of: all, cmi, bof"
    )


DANGER_FUNC_TYPES: Dict[str, str] = build_selected_danger_func_types(DANGER_FUNC_MODE)
DANGER_FUNCS: Set[str] = set(DANGER_FUNC_TYPES)
IMPORT_SYMBOL_TYPES = {
    binaryninja.SymbolType.ImportAddressSymbol,
    binaryninja.SymbolType.ImportedFunctionSymbol,
}


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

    print(colored(f"[*] [Lib Scan] Scanning firmware root: {root_dir}", "cyan"))

    file_map = {}

    print(colored("    [Info] Building filename index...", "blue"))
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
                                print(colored(f"    [+] Resolved pseudo-link: {lib_name} -> {target_filename}", "green"))
                                so_files.append(real_path)
                                found_real = True
                        if not found_real:
                            print(colored(f"    [-] Invalid ELF target: {lib_name} -> {target_filename}", "red"))
                    else:
                        print(colored(f"    [-] Missing target file: {lib_name} -> {target_filename}", "red"))

    unique_so_files = list(set(so_files))
    return unique_so_files


def get_function_sourcecode_in_HLIL(bv, function_name):
    current_function = bv.get_functions_by_name(function_name)[0]
    hlil_code = '\n'.join(map(str, current_function.hlil.root.lines))
    return hlil_code


def collect_dangerous_caller_details(bv, danger_func_types: Dict[str, str]) -> Dict[str, Dict[str, str]]:
    caller_to_danger_funcs: Dict[str, Dict[str, str]] = {}
    for danger_func_name, danger_type in danger_func_types.items():
        symbols = bv.get_symbols_by_name(danger_func_name)
        if not symbols:
            continue
        for symbol in symbols:
            if symbol.type not in IMPORT_SYMBOL_TYPES:
                continue
            for ref in bv.get_code_refs(symbol.address):
                caller_name = ref.function.name
                if not caller_name:
                    continue
                caller_to_danger_funcs.setdefault(caller_name, {})[danger_func_name] = danger_type
    return caller_to_danger_funcs


def _format_dangerous_calls(dangerous_calls: List[Dict[str, str]]) -> str:
    if not dangerous_calls:
        return "- None"
    return "\n".join(
        f"- {item['name']} [{item['type']}]"
        for item in dangerous_calls
    )


def build_batch_user_instruction(
    batch_funcs: List[str],
    func_hlil_map: Dict[str, str],
    func_danger_map: Dict[str, List[Dict[str, str]]],
) -> str:
    parts: List[str] = []
    for func_name in batch_funcs:
        danger_text = _format_dangerous_calls(func_danger_map.get(func_name, []))
        parts.append(
            f"Function Name: {func_name}\n"
            f"Dangerous Standard Calls:\n{danger_text}\n"
            f"HLIL:\n{func_hlil_map[func_name]}"
        )
        parts.append("----------------------------------------")
    return "\n".join(parts)


def _strip_code_fences(raw_text: str) -> str:
    text = raw_text.strip()
    if not text.startswith("```"):
        return text

    lines = text.splitlines()
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _unwrap_llm_response_object(obj: Any):
    if isinstance(obj, list):
        if len(obj) == 1 and isinstance(obj[0], dict):
            return obj[0], ["unwrapped single-item list"]
        return None, [f"unexpected list length {len(obj)}"]
    if isinstance(obj, dict):
        return obj, []
    return None, [f"unexpected top-level type {type(obj).__name__}"]


def _normalize_llm_key(key: Any) -> str:
    text = str(key).strip().strip("`").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        text = text[1:-1].strip()
    return text


def _normalize_llm_value(value: Any) -> str:
    if value is None:
        return "None"
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False)
    except TypeError:
        return str(value)


def parse_llm_batch_response(raw_result: str):
    text = raw_result.strip()
    if not text:
        return None, [], "empty response"

    repair_notes: List[str] = []
    candidates = [("raw json", text, "json")]

    stripped = _strip_code_fences(text)
    if stripped != text:
        candidates.append(("code fence stripped", stripped, "json"))

    if "{" in stripped and "}" in stripped:
        json_fragment = stripped[stripped.find("{"): stripped.rfind("}") + 1].strip()
        if json_fragment and json_fragment not in {candidate[1] for candidate in candidates}:
            candidates.append(("json fragment extracted", json_fragment, "json"))

    for label, candidate_text, parser in list(candidates):
        if parser == "literal":
            continue
        candidates.append((f"{label} via literal_eval", candidate_text, "literal"))

    parse_errors: List[str] = []
    seen_candidates = set()

    for label, candidate_text, parser in candidates:
        dedup_key = (candidate_text, parser)
        if dedup_key in seen_candidates:
            continue
        seen_candidates.add(dedup_key)

        try:
            obj = json.loads(candidate_text) if parser == "json" else ast.literal_eval(candidate_text)
        except Exception as exc:
            parse_errors.append(f"{label}: {exc}")
            continue

        obj, unwrap_notes = _unwrap_llm_response_object(obj)
        if obj is None:
            parse_errors.append(f"{label}: {'; '.join(unwrap_notes)}")
            continue

        normalized = {_normalize_llm_key(k): _normalize_llm_value(v) for k, v in obj.items()}
        repair_notes.extend(unwrap_notes)
        if label != "raw json":
            repair_notes.append(label)
        return normalized, repair_notes, None

    error_message = " | ".join(parse_errors) if parse_errors else "unknown parse failure"
    return None, repair_notes, error_message


def update_failure_counts(failure_counts: Dict[str, int], failed_funcs: List[str]):
    retry_funcs: List[str] = []
    dropped_funcs: List[str] = []

    for func in failed_funcs:
        failure_counts[func] = failure_counts.get(func, 0) + 1
        if failure_counts[func] >= MAX_LLM_FAILURES:
            dropped_funcs.append(func)
        else:
            retry_funcs.append(func)

    return retry_funcs, dropped_funcs


def is_none_like(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and value.strip().lower() == "none":
        return True
    return False
STRING_COPY_FUNCS: Set[str] = {
    "sprintf",
    "vsprintf",
    "snprintf",
    "vsnprintf",
    "strcat",
    "strncat",
    "fprintf"
}


def _to_var(v: Union[Variable, SSAVariable]) -> Variable:
    return v.var if isinstance(v, SSAVariable) else v


def _vars_read(instr: MediumLevelILInstruction) -> Set[Variable]:
    return {_to_var(v) for v in instr.vars_read}


def _vars_written(instr: MediumLevelILInstruction) -> Set[Variable]:
    return {_to_var(v) for v in instr.vars_written}


def _extract_called_function_name(bv, instr: MediumLevelILInstruction) -> str | None:
    if instr.operation not in {MediumLevelILOperation.MLIL_CALL_SSA,
                               MediumLevelILOperation.MLIL_TAILCALL_SSA,
                               MediumLevelILOperation.MLIL_CALL,
                               MediumLevelILOperation.MLIL_TAILCALL}:
        return None
    callee = bv.get_symbol_at(instr.dest.constant)
    if callee:
        return callee.name
    return None


def _extract_variables(expr: MediumLevelILInstruction) -> Set[Variable]:
    out: Set[Variable] = set()
    if expr.operation in {MediumLevelILOperation.MLIL_VAR_SSA, MediumLevelILOperation.MLIL_VAR}:
        out.add(_to_var(expr.src))
    for op in expr.operands:
        if isinstance(op, MediumLevelILInstruction):
            out.update(_extract_variables(op))
    return out


def get_definitions(func: Function, var: Variable) -> List[MediumLevelILInstruction]:
    return [ins for blk in func.mlil.ssa_form for ins in blk if var in _vars_written(ins)]


def get_usages(func: Function, var: Variable) -> List[MediumLevelILInstruction]:
    return [ins for blk in func.mlil.ssa_form for ins in blk if var in _vars_read(ins)]


def _handle_set_var(instr: MediumLevelILInstruction) -> Iterable[Variable]:
    return _vars_read(instr)


def _handle_set_var_use(instr: MediumLevelILInstruction) -> Iterable[Variable]:
    return _vars_written(instr)


def _handle_load_store(instr: MediumLevelILInstruction, var: Variable) -> Iterable[Variable]:
    return (v for v in _vars_read(instr) if v != var)


def _handle_string_copy_call(
    bv, instr: MediumLevelILInstruction, var: Variable
) -> Iterable[Variable]:
    callee = _extract_called_function_name(bv, instr)
    if callee not in STRING_COPY_FUNCS:
        return ()
    out: Set[Variable] = set()
    for p in instr.params[1:]:
        out.update(_extract_variables(p))
    return out


def get_all_sink_addr(bv, current_function):
    address_list = set()
    for il in current_function.mlil.ssa_form:
        for ins in il:
            if ins.operation in {MediumLevelILOperation.MLIL_CALL_SSA,
                                 MediumLevelILOperation.MLIL_TAILCALL_SSA,
                                 MediumLevelILOperation.MLIL_CALL,
                                 MediumLevelILOperation.MLIL_TAILCALL}:
                callee = _extract_called_function_name(bv, ins)
                if callee in ['system', 'execv', 'popen', 'execve']:
                    address_list.add(ins.address)
    return address_list


def _collect_next_variables(bv, instr: MediumLevelILInstruction, var: Variable) -> Set[Variable]:
    op = instr.operation
    if op in {MediumLevelILOperation.MLIL_SET_VAR_SSA, MediumLevelILOperation.MLIL_SET_VAR,
              MediumLevelILOperation.MLIL_VAR_PHI, MediumLevelILOperation.MLIL_SET_VAR_ALIASED}:
        a = set(_handle_set_var(instr))
        return a
    if op in {MediumLevelILOperation.MLIL_LOAD_SSA, MediumLevelILOperation.MLIL_STORE_SSA}:
        return set(_handle_load_store(instr, var))
    if op in {MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA}:
        return set(_handle_string_copy_call(bv, instr, var))
    return set()


def _collect_next_variables_use(bv, instr: MediumLevelILInstruction, var: Variable) -> Set[Variable]:
    op = instr.operation
    if op in {MediumLevelILOperation.MLIL_SET_VAR_SSA, MediumLevelILOperation.MLIL_SET_VAR,
              MediumLevelILOperation.MLIL_VAR_PHI}:
        return set(_handle_set_var_use(instr))
    if op in {MediumLevelILOperation.MLIL_LOAD_SSA, MediumLevelILOperation.MLIL_STORE_SSA}:
        return set(_handle_load_store(instr, var))
    if op in {MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA}:
        return set(_handle_string_copy_call(bv, instr, var))
    return set()


def identify_sink_parameters(bv, func: Function, dangerous_callsite_addr: int) -> Set[Variable]:
    call_il: MediumLevelILInstruction | None = None
    for bl in func.mlil.ssa_form:
        for ins in bl:
            if ins.address == dangerous_callsite_addr:
                call_il = ins
                break
        if call_il:
            break

    if call_il is None:
        print(f"[use-def] 0x{dangerous_callsite_addr:x} not found in MLIL SSA")
        return set()

    worklist: List[Variable] = []
    visited: Set[Variable] = set()
    for arg in call_il.params:
        worklist.extend(_extract_variables(arg))

    while worklist:
        cur = worklist.pop()
        if cur in visited:
            continue
        visited.add(cur)
        for d in get_definitions(func, cur):
            worklist.extend(v for v in _collect_next_variables(bv, d, cur) if v not in visited)
        for u in get_usages(func, cur):
            worklist.extend(v for v in _collect_next_variables_use(bv, u, cur) if v not in visited)

    return {v for v in visited if v in func.parameter_vars}


def _parse_addr(val: str) -> int:
    return int(val, 16) if val.startswith("0x") else int(val)


def _resolve_func(bv, ident: str) -> Function | None:
    if ident.startswith("0x") or ident.isdigit():
        return bv.get_function_at(_parse_addr(ident))
    syms = bv.get_symbols_by_name(ident)
    if syms:
        return bv.get_function_at(syms[0].address)
    return None

def generate(systemInstruction, userInstruction, func_num):
    if func_num == 0:
        return "{}"

    config = get_llm_config("sink")
    client = OpenAI(
        api_key=config["api_key"],
        base_url=config["base_url"],
    )

    messages = [
        {"role": "system", "content": systemInstruction},
        {"role": "user", "content": userInstruction}
    ]

    try:
        response = client.chat.completions.create(
            model=config["model"],
            messages=messages,
            temperature=0,
            top_p=0.95,
            response_format={"type": "json_object"},
            stream=False,
        )

        if not response.choices:
            print(colored("[-] API Error: empty choices in non-stream response", "red"))
            return "{}"

        content = response.choices[0].message.content
        if not content:
            return "{}"

        return content

    except Exception as e:
        print(colored(f"[-] API Error: {str(e)}", "red"))
        return "{}"


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} path_to_binary path_to_firmware_root")
        sys.exit(1)

    danger_func = DANGER_FUNCS
    binary_path = sys.argv[1]
    root_dir = sys.argv[2]
    print(colored(
        f"[*] [Config] DANGER_FUNC_MODE={DANGER_FUNC_MODE}, enabled danger funcs={sorted(danger_func)}",
        "cyan"
    ))

    print(colored(f"[*] [Phase 0] Loading binary: {binary_path}", "cyan"))
    bv = binaryninja.load(binary_path)

    print(colored(f"[*] [Phase 1] Resolving dependent libraries for: {binary_path}", "cyan"))
    excluded_prefixes = ("libc.so", "libpthread.so", "libgcc")
    libraries_list = [lib for lib in bv.libraries if not lib.startswith(excluded_prefixes)]
    libraries_path_list = find_so_files(root_dir, libraries_list)
    print(colored(f"[#] [Phase 1] Resolved {len(libraries_path_list)} candidate shared libraries", "magenta"))

    print(colored(f"[*] [Phase 2] Scanning imported functions of main binary", "cyan"))
    ImportedFunctionList = set()
    candidate_sink = set()
    candidate_func_hlil: Dict[str, str] = {}
    candidate_func_danger_info: Dict[str, List[Dict[str, str]]] = {}
    func_so_info = {}
    candidate_func_num = 0

    for function in bv.functions:
        if function.symbol.type == binaryninja.SymbolType.ImportedFunctionSymbol:
            ImportedFunctionList.add(function.name)
    bv.file.close()

    print(colored(
        f"[#] [Phase 2] Found {len(ImportedFunctionList)} imported functions, start resolving sink candidates",
        "magenta"
    ))

    for so_file in sorted(libraries_path_list):
        func_so_info[so_file] = set()
        bv = binaryninja.load(so_file)
        caller_danger_details = collect_dangerous_caller_details(bv, DANGER_FUNC_TYPES)
        current_lib_sink = set(ImportedFunctionList & set(caller_danger_details))

        for func in sorted(current_lib_sink):
            if func not in (candidate_sink | danger_func):
                func_so_info[so_file].add(func)
                current_functions = bv.get_functions_by_name(func)[0]
                candidate_func_hlil[func] = (
                    str(current_functions) + "\n" +
                    get_function_sourcecode_in_HLIL(bv, func)
                )
                candidate_func_danger_info[func] = [
                    {"name": name, "type": danger_type}
                    for name, danger_type in sorted(caller_danger_details.get(func, {}).items())
                ]
                candidate_func_num += 1

        new_add_sink = {func for func in current_lib_sink if func not in (candidate_sink | danger_func)}
        candidate_sink = candidate_sink.union(new_add_sink)

        if new_add_sink:
            print(colored(
                f"    [+] {os.path.basename(so_file)} matched sink-like exports: {sorted(new_add_sink)}",
                "green"
            ))
        else:
            print(colored(
                f"    [!] {os.path.basename(so_file)} matched no sink-like exports",
                "yellow"
            ))

        print(colored(f"    [#] Current unique candidate count: {len(candidate_sink)}", "magenta"))
        bv.file.close()

    print(colored(
        f"[#] [Phase 2] Cached HLIL for {candidate_func_num} candidate functions, ready for batched LLM analysis",
        "magenta"
    ))

    print(colored(f"[*] [Phase 3] Querying LLM for sink-parameter inference...", "cyan"))
    print(colored(f"    [#] LLM_BATCH_SIZE={LLM_BATCH_SIZE}, MAX_LLM_FAILURES={MAX_LLM_FAILURES}", "magenta"))

    pending_funcs = list(candidate_func_hlil.keys())
    failure_counts = {func: 0 for func in pending_funcs}
    dropped_funcs: List[str] = []
    resolved_results: Dict[str, str] = {}
    batch_idx = 0

    while pending_funcs:
        batch_idx += 1
        batch_funcs = pending_funcs[:LLM_BATCH_SIZE]
        pending_funcs = pending_funcs[LLM_BATCH_SIZE:]
        userInstruction = build_batch_user_instruction(
            batch_funcs,
            candidate_func_hlil,
            candidate_func_danger_info,
        )

        print(colored(
            f"[*] [Phase 3][Batch {batch_idx}] Running {len(batch_funcs)} functions",
            "cyan"
        ))
        print(colored(f"    [#] Batch functions: {batch_funcs}", "magenta"))

        raw_result = generate(systemInstruction_Template, userInstruction, len(batch_funcs)).strip()
        batch_response, repair_notes, parse_error = parse_llm_batch_response(raw_result)

        if repair_notes:
            print(colored(f"    [Info] Response repairs applied: {repair_notes}", "blue"))

        if batch_response is None:
            retry_funcs, batch_dropped = update_failure_counts(failure_counts, batch_funcs)
            dropped_funcs.extend(batch_dropped)
            print(colored(
                f"    [-] Batch parse failed after repair, retrying entire batch. failed={len(batch_funcs)}",
                "red"
            ))
            print(colored(f"    [Reason] {parse_error}", "yellow"))
            preview = raw_result[:500] if raw_result else "<empty response>"
            print(colored(f"    [Preview] {preview}", "yellow"))
            print(colored(f"    [#] Batch {batch_idx} success=0 failed={len(batch_funcs)}", "magenta"))
            if retry_funcs:
                print(colored(
                    f"    [!] Move to next batch ({len(retry_funcs)}): {retry_funcs}",
                    "yellow"
                ))
                pending_funcs = retry_funcs + pending_funcs
            if batch_dropped:
                print(colored(
                    f"    [-] Dropped after {MAX_LLM_FAILURES} consecutive failures: {batch_dropped}",
                    "red"
                ))
            continue

        missing_funcs: List[str] = []
        for func in batch_funcs:
            if func in batch_response:
                resolved_results[func] = batch_response[func]
            else:
                missing_funcs.append(func)

        retry_funcs, batch_dropped = update_failure_counts(failure_counts, missing_funcs)
        dropped_funcs.extend(batch_dropped)
        success_count = len(batch_funcs) - len(missing_funcs)

        print(colored(
            f"    [#] Batch {batch_idx} success={success_count} failed={len(missing_funcs)}",
            "magenta"
        ))

        if retry_funcs:
            print(colored(
                f"    [!] Missing in LLM response, move to next batch ({len(retry_funcs)}): {retry_funcs}",
                "yellow"
            ))
            pending_funcs = retry_funcs + pending_funcs

        if batch_dropped:
            print(colored(
                f"    [-] Dropped after {MAX_LLM_FAILURES} consecutive failures: {batch_dropped}",
                "red"
            ))

        if not missing_funcs:
            print(colored("    [+] Batch finished successfully with complete coverage", "green"))

    final_result = {
        k: v for k, v in resolved_results.items()
        if k not in danger_func and not is_none_like(v)
    }

    if dropped_funcs:
        print(colored(
            f"[#] [Phase 3] Dropped {len(dropped_funcs)} functions after repeated LLM failures: {dropped_funcs}",
            "yellow"
        ))

    print(colored(f"[#] [Done] Final non-empty sink results: {len(final_result)}", "magenta"))
    print(final_result)
