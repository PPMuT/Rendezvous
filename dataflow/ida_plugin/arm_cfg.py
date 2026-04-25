#!/usr/bin python
import sys
import os
import time

from idc import *
from idautils import *
from idaapi import *
from ida_nalt import *
from ida_funcs import *

from struct import pack
from ctypes import c_uint32, c_uint64
import subprocess
from collections import defaultdict
import json

file_name = get_root_filename()
save_path = os.path.dirname(get_input_file_path())

base = get_imagebase()
plt_start, plt_end = 0, 0
segments = list(Segments())

dump_vtables = False
vtable_section_names = [".rodata",
    ".data.rel.ro",
    ".data.rel.ro.local",
    ".rdata"]

got_file = ""
vtables_ptrs = set()
data_xref_addrs = {}

pure_virtual_addr = 0x7F8894
number_allowed_zero_entries = 2

is_linux = None
is_windows = None


def data_xref_from(ea):
    return [x for x in DataRefsFrom(ea)]

def data_xref_to(ea):
    return [x for x in DataRefsTo(ea)]

def collect_data_xref_to(xref_addrs, xref_type=None):
    for xref_addr, data in xref_addrs.items():
        if xref_type == 'func' and not is_code_region(xref_addr):
            continue

        if xref_addr not in data_xref_addrs:
            data_xref_addrs[xref_addr] = data

def is_code_region(addr):
    if sections['.text'][0] <= addr < sections['.text'][1]:
        return True
    return False


def is_rodata_region(addr):

    for data_section in data_sections:
        seg_name = idc.get_segm_name(data_section)
        if seg_name == '.rodata' and idc.get_segm_start(data_section) <= addr <= idc.get_segm_end(data_section):
            return True
    return False

def get_relocation_entries_gcc64(elf_file):

    relocation_entries = set()

    try:
        result = subprocess.check_output(
            ['readelf', '--relocs', elf_file])
    except:
        raise Exception("Not able to extract relocation entries.")

    for line in result.split('\n')[3:]:
        line = line.split()

        try:
            rel_offset = int(line[0], 16)
            relocation_entries.add(rel_offset)
        except:
            continue

    return relocation_entries


def data_xref(ea):
    return [x for x in DataRefsFrom(ea)]


def get_vptr_xref(address):
    vtable_ptr = None
    for curr_addr in data_xref(address):
        may_vptr = curr_addr
        if got_start <= curr_addr < got_end:
            may_vptr = idc.get_qword(curr_addr)

        if any(map(lambda x: idc.get_segm_start(x) <= may_vptr <= idc.get_segm_end(x), vtable_sections)):

            if (may_vptr in vtables_ptrs or
                    (may_vptr+16) in vtables_ptrs or
                    (may_vptr+8) in vtables_ptrs):
                vtable_ptr = may_vptr
                print("Find vptr 1: %x" % (vtable_ptr))
                break

            else:
                ptr2data = idc.get_qword(may_vptr)
                if ptr2data in vtables_ptrs:
                    vtable_ptr = may_vptr
                    print("Find vptr 2: %x" % (vtable_ptr))

    return vtable_ptr

def get_plt_jmp_addr_gcc64(funcea):
    for ea in FuncItems(funcea):
        if (idc.print_insn_mnem(ea) == 'jmp' and idc.get_operand_type(ea, 0) == 2):
            for data in data_xref(ea):
                if arch_bits == 64:
                    return idc.get_qword(data)
                else:
                    return get_wide_dword(data)
    return None

def test_jmp():
    ea = 0x404078
    print("OpTye: ", idc.get_operand_type(ea, 0))
    v_opnd1 = idc.get_operand_value(ea, 0)
    addr = idc.get_func_attr(v_opnd1, 0)
    if addr != BADADDR:
        print("Jmp function: 0x%x" % (addr))


def get_function_ptr(address, bb_info):
    for curr_addr in data_xref_from(address):
        if text_start <= curr_addr <= text_end:
            func_addr = idc.get_func_attr(curr_addr, 0)
            if func_addr == curr_addr:
                print("%x has func pointer: %x" % (address, func_addr))
                info = (address, func_addr, 'func_ptr')
                bb_info.append(info)

        elif got_start <= curr_addr < got_end:
            if arch_bits == 64:
                may_ptr = idc.get_qword(curr_addr)
            else:
                may_ptr = get_wide_dword(curr_addr)
            func_addr = may_ptr
            if plt_start <= may_ptr <= plt_end:
                func_addr = get_plt_jmp_addr_gcc64(may_ptr)

            if func_addr:
                if extern_start <= func_addr <= extern_end:
                    start_addr = idc.get_func_attr(func_addr, 0)
                    if func_addr == start_addr:
                        func_name = idc.get_func_name(func_addr)
                        info = (address, func_name, 'ext_ptr')
                        bb_info.append(info)
                        print("%x has extern func: %x, %s" % (address, func_addr, func_name))
                    else:
                        extern_name = idc.get_name(func_addr, ida_name.GN_VISIBLE)
                        info = (address, extern_name, 'ext_data')
                        bb_info.append(info)
                        print("%x has extern data: %x, %s" % (address, func_addr, extern_name))

                elif text_start <= func_addr <= text_end:
                    start_addr = idc.get_func_attr(func_addr, 0)
                    if func_addr == start_addr:
                        info = (address, func_addr, 'func_ptr')
                        bb_info.append(info)
                        print("%x has func pointer: %x" % (address, func_addr))

def generate_cg(funcea, block, func_info):
    bb_info = []
    find_switch = None
    ins_addrs = set()
    block_start, block_end = block.start_ea, block.end_ea
    ea = block_start
    ins_addrs.add(ea)
    while ea != BADADDR and ea < block_end:
        mnem = idc.print_insn_mnem(ea)
        if mnem == 'call':
            v_opnd1 = idc.get_operand_value(ea, 0)
            if data_start <= v_opnd1 < data_end:
            	v_opnd1 = idc.get_qword(v_opnd1)
            addr = idc.get_func_attr(v_opnd1, 0)
            if addr != BADADDR:
                if plt_start <= addr <= plt_end:
                    func_addr = get_plt_jmp_addr_gcc64(addr)
                    if func_addr:
                        if extern_start <= func_addr <= extern_end:
                            func_name = idc.get_func_name(func_addr)
                            func_info['call'].append((block_start, ea, func_name))
                        else:
                            func_info['call'].append((block_start, ea, func_addr))
                else:
                    func_info['call'].append((block_start, ea, addr))

            else:
                bb_info.append((ea, None, 'iCall'))

        elif mnem == 'jmp':
            opnd0_type = idc.get_operand_type(ea, 0)
            if opnd0_type == 7:
                v_opnd1 = idc.get_operand_value(ea, 0)
                addr = idc.get_func_attr(v_opnd1, 0)
                if addr != BADADDR and addr != funcea:
                    if plt_start <= addr <= plt_end:
                        func_addr = get_plt_jmp_addr_gcc64(addr)
                        if func_addr:
                            if extern_start <= func_addr <= extern_end:
                                func_name = idc.get_func_name(func_addr)
                                func_info['call'].append((block_start, ea, func_name))

                            else:
                                func_info['call'].append((block_start, ea, func_addr))

                    elif text_start <= addr <= text_end:
                        func_info['call'].append((block_start, ea, addr))

            elif opnd0_type == 1:
                opnd1 = idc.print_operand(ea, 0)
                bb_info.append((ea, None, 'iCall'))

            elif opnd0_type == 2:
            	find_switch = ea

        vtable_ptr = get_vptr_xref(ea)
        if vtable_ptr:
            bb_info.append((ea, vtable_ptr, 'xref_vptr'))

        get_function_ptr(ea, bb_info)

        ea = idc.next_head(ea)
        if ea in ins_addrs:
            break
        else:
            ins_addrs.add(ea)

    func_name = '%x' % (funcea)
    if func_name not in blocks_record:
        blocks_record[func_name] = {}

    if bb_info:
        blocks_record[func_name][block_start] = bb_info

    return find_switch


def memory_accessible(addr):
    for segment in segments:
        if idc.get_segm_start(segment) <= addr < idc.get_segm_end(segment):
            return True
    return False

def check_entry_valid_gcc64(addr, qword):

    ptr_to_text = (text_start <= qword < text_end)

    if ptr_to_text:
    	func_addr = idc.get_func_attr(qword, 0)
    	ptr_to_text = (qword == func_addr)

    ptr_to_extern = (extern_start <= qword < extern_end)
    ptr_to_plt = (plt_start <= qword < plt_end)

    is_relocation_entry = ((addr in relocation_entries)
        and not any(map(
        lambda x: idc.get_segm_start(x) <= qword <= idc.get_segm_end(x), vtable_sections)))

    if (ptr_to_text
        or ptr_to_extern
        or ptr_to_plt
        or qword == pure_virtual_addr
        or is_relocation_entry):
        return True
    return False


def get_vtable_entries_gcc64(vtables_offset_to_top):

    global vtables_ptrs
    vtable_entries = dict()


    for vtable_addr in vtables_offset_to_top.keys():

        curr_addr = vtable_addr
        curr_qword = idc.get_qword(curr_addr)
        entry_ctr = 0
        vtable_entries[vtable_addr] = list()
        vtables_ptrs.add(vtable_addr)
        while (check_entry_valid_gcc64(curr_addr, curr_qword)
            or (entry_ctr < number_allowed_zero_entries and curr_qword == 0)):

            vtable_entries[vtable_addr].append(curr_qword)

            curr_addr += 8
            entry_ctr += 1
            curr_qword = idc.get_qword(curr_addr)

    return vtable_entries

def get_vtables_gcc64():

    vtables_offset_to_top = dict()

    def check_rtti_and_offset_to_top(rtti_candidate, ott_candidate, addr):
        ott_addr = addr - 16
        offset_to_top = ctypes.c_longlong(ott_candidate).value
        ott_valid = (-0xFFFFFF <= offset_to_top and offset_to_top <= 0xffffff)
        rtti_valid = (rtti_candidate == 0
            or (not text_start <= rtti_candidate < text_end
            and memory_accessible(rtti_candidate)))

        ott_no_rel = (not ott_addr in relocation_entries)

        if ott_valid and rtti_valid and ott_no_rel:
            return True
        return False


    for vtable_section in vtable_sections:
        i = idc.get_segm_start(vtable_section)
        qword = 0
        prevqword = 0

        while i <= idc.get_segm_end(vtable_section) - 8:

            pprevqword = prevqword
            prevqword = qword
            qword = Qword(i)
            is_zero_entry = (qword == 0)

            if check_entry_valid_gcc64(i, qword):
                if check_rtti_and_offset_to_top(prevqword, pprevqword, i):


                    offset_to_top = ctypes.c_longlong(pprevqword).value
                    vtables_offset_to_top[i] = offset_to_top

                while (check_entry_valid_gcc64(i, qword)
                    and i < (idc.get_segm_end(vtable_section) - 8)):

                    i += 8
                    prevqword = qword
                    qword = Qword(i)
            elif (is_zero_entry
                and (i-16) >= idc.get_segm_start(vtable_section)
                and check_rtti_and_offset_to_top(prevqword, pprevqword, i)):

                for j in range(1, number_allowed_zero_entries+1):

                    if (i+(j*8)) <= (idc.get_segm_end(vtable_section)-8):

                        nextqword = idc.get_qword(i+(j*8))

                        if nextqword == 0:
                            continue

                        if check_entry_valid_gcc64(i+(j*8), nextqword):
                            offset_to_top = ctypes.c_longlong(pprevqword).value
                            vtables_offset_to_top[i] = offset_to_top
                            break
                        else:
                            break

                    else:
                        break

            i += 8
    for vtable in list(vtables_offset_to_top.keys()):
        for i in range(1, number_allowed_zero_entries+1):
            if (vtable + i*8) in vtables_offset_to_top.keys():

                if not list(XrefsTo(vtable + i*8)):
                    if (vtable + i*8) in vtables_offset_to_top.keys():
                        del vtables_offset_to_top[(vtable + i*8)]
                    continue

                if not list(XrefsTo(vtable)):
                    if vtable in vtables_offset_to_top.keys():
                        del vtables_offset_to_top[vtable]
                    continue

    return vtables_offset_to_top

def process_function(function):
    dump = pack('<I', function - base)
    flow = FlowChart(get_func(function))
    assert len(dump) == 4

    block_dump, block_count = '', 0
    for block in flow:
        block_start = block.start_ea
        block_end = block.end_ea

        if plt_start <= block_start < plt_end:
            continue

        address, instruction_count = block_start, 0
        while address != BADADDR and address < block_end:
            instruction_count += 1
            address = idc.next_head(address)

        block_dump += pack('<I', block_start - base)
        block_dump += pack('<I', block_end - block_start)
        block_dump += pack('<H', instruction_count)

        block_count += 1

    dump += pack('<H', block_count)
    dump += block_dump
    return dump


def get_all_functions():

    global segments

    if '.plt' in sections:
        plt_start, plt_end = sections['.plt']
    else:
        plt_start, plt_end = 0, 0

    code_start, code_end = 0xF000000000000000, 0x0
    funcs = set()
    function_count = 0

    for segment in segments:
        permissions = getseg(segment).perm
        if not permissions & SEGPERM_EXEC:
            continue

        if idc.get_segm_start(segment) == plt_start:
            continue

        print('\nProcessing segment %s.' % idc.get_segm_name(segment))
        for i, function in enumerate(Functions(idc.get_segm_start(segment), idc.get_segm_end(segment))):
            funcs.add(function)

            function_count += 1
            if function < code_start:
                code_start = function
            if function > code_end:
                code_end = function

    print('\nExported %d functions.' % function_count)
    if '.text' not in sections:
        end_func = get_func(code_end)
        code_end = end_func.end_ea
        sections['.text'] = (code_start, code_end)

    return funcs


def generate_cg_bak():
    cg_record = {}
    for funcea in [0x5f25d0]:
        func_start = idc.get_func_attr(funcea, 0)
        func_end = idc.get_func_attr(funcea, 4)
        call_edge = []
        for ea in FuncItems(funcea):
            ins = GetDisasm(ea)
            mnem = idc.print_insn_mnem(ea)
            if mnem == 'call':
                v_opnd1 = idc.get_operand_value(ea, 0)
                opnd1 = idc.print_operand(ea, 0)
                # print ins, opnd1, v_opnd1
                addr = idc.get_func_attr(v_opnd1, 0)
                if addr != BADADDR:
                    call_edge.append((ea, addr, 'Call'))
                    # print addr
                else:
                    call_edge.append((ea, opnd1, 'iCall'))
            elif mnem == 'jmp':
                v_opnd1 = idc.get_operand_value(ea, 0)
                opnd1 = idc.print_operand(ea, 0)
                # print ins, opnd1, v_opnd1
                if 'loc' in opnd1 or '*' in opnd1:
                    continue
                else:
                    addr = idc.get_func_attr(v_opnd1, 0)
                    if addr != BADADDR and addr != funcea:
                        # print 'addr: ', addr
                        call_edge.append((ea, addr, 'Call'))
                    else:
                        call_edge.append((ea, opnd1, 'iCall'))
        cg_record[funcea] = call_edge

def generate_cfg_bak2(cfg_record, funcs):
    node_list = []
    ea = SegByBase(idc.selector_by_name(".text"))
    # for funcea in [0x25a9c0]:
    for funcea in Functions(idc.get_segm_start(ea), idc.get_segm_end(ea)):
        func_info = {'block': [], 'jmp': [], 'call': []}
        node_record = set()
        func = idaapi.get_func(funcea)
        fc = idaapi.FlowChart(func)
        init_block = fc[0]
        node_list.append(init_block)
        node_record.add(init_block.start_ea)
        func_info['block'].append((init_block.start_ea, init_block.end_ea))

        while node_list:
            n = node_list.pop()
            generate_cg(funcea, n, func_info)
            for succ_bl in n.succs():
                if plt_start <= succ_bl.start_ea <= plt_end:
                    continue
                if succ_bl.start_ea in funcs:
                    continue
                func_info['jmp'].append((n.start_ea, succ_bl.start_ea))
                if succ_bl.start_ea not in node_record:
                    node_record.add(succ_bl.start_ea)
                    node_list.append(succ_bl)
                    func_info['block'].append((succ_bl.start_ea, succ_bl.end_ea))

        funcea_name = '%x' % funcea
        cfg_record[funcea_name] = func_info



def test_path():
    global work_path
    print("work path: %s" % (work_path))


def resolve_switch(ea):
	ins = GetDisasm(ea)

	mnem = idc.print_insn_mnem(ea)

	opnd1 = idc.print_operand(ea, 0)

	opnd_value = idc.get_operand_value(ea, 0)

	switch_targets = set()
	if mnem == 'jmp' and ('*' in opnd1 and 'ds' in opnd1):
		if any(map(lambda x: idc.get_segm_start(x) <= opnd_value <= idc.get_segm_end(x), vtable_sections)):
			print("%x %s" % (ea, ins))
			xref_falg = False
			addr = opnd_value
			while True:
				r_value = idc.get_qword(addr)
				if text_start <= r_value < text_end:
					switch_targets.add(r_value)
					# print("Find loc_%x" % (r_value))
					addr += 8
					for xref in XrefsTo(addr, 0):
						xref_falg = True
						break

					if xref_falg:
						break

				else:
					break

	for target in switch_targets:
		print("switch_target: %x" % (target))
	return switch_targets


def resolve_call_target(ea):
	mnem = idc.print_insn_mnem(ea)

	opnd1 = idc.print_operand(ea, 0)

	opnd_value = idc.get_operand_value(ea, 0)

	print("%s" % (opnd1))
	print("%x" % (opnd_value))

	if data_start <= opnd_value < data_end:
		qdata = idc.get_qword(opnd_value)
		print("%x" % (qdata))


def recognise_function_gcc32_v1(functions):
    global segments, sections
    choose_areas = []
    if '.data' in choose_areas:
        choose_areas.append(sections['.data'])
    else:
        for segment in segments:
            permissions = getseg(segment).perm
            if permissions == 6:
                choose_areas.append((idc.get_segm_start(segment), idc.get_segm_end(segment)))

    for start, end in choose_areas:
        xref_addrs = {}
        i = start
        while i <= end:
            x = get_wide_dword(i)
            xrefs_to = data_xref_to(i)
            if xrefs_to:
                xref_addrs.clear()
                for xref_addr in xrefs_to:
                    xref_addrs[xref_addr] = i

            if is_code_region(x):
                if x in functions:
                    print(" 0x%x : %x" % (i, x))
                    if xref_addrs:
                        collect_data_xref_to(xref_addrs, xref_type='func')

                else:
                    mnem = idc.print_insn_mnem(x)
                    opnd0_name = idc.print_operand(x, 0)
                    ins = GetDisasm(x)
                    print(" 0x%x : %x" % (i, x))
                    # print("%s" % (ins))
                    func = get_func(x)
                    if func is None:
                        ida_funcs.add_func(x)
                        func = get_func(x)
                        print("Get-func: %s" % (func))

                    if xref_addrs:
                        collect_data_xref_to(xref_addrs, xref_type='func')

            i += 4


def recognise_functions(functions):
    print("Arch-bits: %s" % (arch_bits))
    # print(info.is_32bit(), info.is_64bit())
    if arch_bits == 32:
        recognise_function_gcc32_v1(functions)

    elif arch_bits == 64:
        raise Exception("64-bits ARM not complete recognise_function_gcc64")
        # recognise_function_gcc64_v1(functions)

def functon_match_v32(ea):

    mnem = idc.print_insn_mnem(ea)
    # ins = GetDisasm(ea)
    if mnem in ['STMFD', 'MOV', 'CMP', 'SUB', 'ADD']:
        return True
    return False

def recovery_functoin_by_traverse_code32(functions, text_start, text_end):
    # print("recovery function in section (%x %x)" % (text_start, text_end))
    ea = text_start
    analyzed_funcs = set()
    while ea < text_end:
        # func = idc.get_func_attr(ea, 0)
        func = get_func(ea)
        # print(" --> %x %s" % (ea, func))
        if func and func.start_ea not in analyzed_funcs:
            analyzed_funcs.add(func.start_ea)
            ea = func.end_ea
            # ea = idc.get_func_attr(ea, 4)
            # print("jmp-> %x" % (ea))
        else:
            flag = functon_match_v32(ea)
            if flag:
                ida_funcs.add_func(ea)
            ea += 4

def recognise_functions_v2(functions):
    if '.text' not in sections:
        print("Could not find text section!")
        return
    text_start, text_end = sections['.text']
    if arch_bits == 32:
        recovery_functoin_by_traverse_code32(functions, text_start, text_end)

    elif arch_bits == 64:
        raise Exception("64-bits ARM not complete recognise_function_gcc64")

def get_switch_block(blocks):
    switch_blocks = {}
    for block in blocks:
        block_start, block_end = block.start_ea, block.end_ea
        ea = block_start
        ins_addrs = {ea}
        print("exit-block: %x" % (block_start))

        while ea != BADADDR and ea < block_end:
            mnem = idc.print_insn_mnem(ea)
            opnd0_name = idc.print_operand(ea, 0)

            if 'LDR' in mnem and opnd0_name in ['PC']:
                switch_blocks[block] = ea

            ea = idc.next_head(ea)
            if ea in ins_addrs:
                break
            else:
                ins_addrs.add(ea)

    return switch_blocks


def get_block_info_arm(funcea, func_end, block, funcs, func_info, blocks_record):
    bb_info = []
    find_switch = None
    ins_addrs = set()
    block_start, block_end = block.start_ea, block.end_ea
    ea = block_start
    ins_addrs.add(ea)
    text_start, text_end = sections['.text']
    # print(".text (%x %x)" % (text_start, text_end))
    while ea != BADADDR and ea < block_end:
        # print("Analysis: 0x%x" % (ea))
        mnem = idc.print_insn_mnem(ea)
        if mnem[:2] == 'BL':
            v_opnd1 = idc.get_operand_value(ea, 0)
            # print('%x' % v_opnd1)
            addr = idc.get_func_attr(v_opnd1, 0)
            attr = idc.get_func_attr(v_opnd1, 8)
            # print("addr: %x" % (addr))

            if addr != BADADDR and v_opnd1 == addr:
                if plt_start <= addr <= plt_end or attr == 0x4c0:
                    # print("Call to addr (PLT): %x" % (addr))
                    func_name = idc.get_func_name(addr)
                    func_info['call'].append((block_start, ea, func_name))
                    # print("Has extern func: %x, %s" % (addr, func_name))

                elif text_start <= addr <= text_end:
                    # print("Has a (%s Call) in 0x%x to 0x%x" % (mnem, ea, addr))
                    func_info['call'].append((block_start, ea, addr))

                elif extern_start <= addr <= extern_end:
                    func_name = idc.get_func_name(addr)
                    func_info['call'].append((block_start, ea, func_name))
                    # print("Has a (%s Extern call) in 0x%x to %s" % (mnem, ea, func_name))

            elif addr == BADADDR:
                opnd0 = idc.print_operand(ea, 0)
                if opnd0 not in ['LR']:
                    # print("Has a indirect (%s Call) in 0x%x" % (mnem, ea))
                    bb_info.append((ea, None, 'iCall'))

        elif mnem in ['B']:
            opnd0_type = idc.get_operand_type(ea, 0)
            # print("opnd0_type: %s" % (opnd0_type))
            if opnd0_type == 7:
                v_opnd1 = idc.get_operand_value(ea, 0)
                addr = idc.get_func_attr(v_opnd1, 0)
                if addr != BADADDR and addr != funcea:
                    if plt_start <= addr <= plt_end:
                        func_name = idc.get_func_name(addr)
                        func_info['call'].append((block_start, ea, func_name))
                        # print("Has a extern (%s Call) in 0x%x to %s" % (mnem, ea, func_name))

                    elif text_start <= addr <= text_end:
                        # print("Has a (B Call) to 0x%x" % (addr))
                        func_info['call'].append((block_start, ea, addr))

                    elif extern_start <= addr <= extern_end:
                        func_name = idc.get_func_name(addr)
                        func_info['call'].append((block_start, ea, func_name))
                        # print("Has a (%s Extern call) in 0x%x to %s" % (mnem, ea, func_name))

            elif opnd0_type == 1:
                opnd1 = idc.print_operand(ea, 0)
                bb_info.append((ea, None, 'iCall'))

        elif mnem in ['MOV', 'LDR']:
            opnd0 = idc.print_operand(ea, 0)
            opnd1 = idc.print_operand(ea, 1)
            if opnd0 == 'PC':
                tmp_ea = idc.next_head(ea)
                if tmp_ea >= block_end and 'SP' in opnd1:
                    print("It's a tail return call, ingore!!!")
                else:
                    bb_info.append((ea, None, 'iCall'))


        if ea in data_xref_addrs:
            data = data_xref_addrs[ea]
            bb_info.append((ea, data, 'data'))

        get_function_ptr(ea, bb_info)

        ea = idc.next_head(ea)
        if ea in ins_addrs:
            break
        else:
            ins_addrs.add(ea)

    funcea_str = '%x' % (funcea)
    if funcea_str not in blocks_record:
        blocks_record[funcea_str] = {}

    if bb_info:
        blocks_record[funcea_str][block_start] = bb_info


def generate_cfg_arm(funcs, cfg_record, blocks_record, switch_record):

    for funcea in funcs:
        # print("funcea: %x" % (funcea))
        try:
            attr = idc.get_func_attr(funcea, 8)
        except:
            attr = 0
        if attr == 0x4c0:
            print("Lib func: %x" % (funcea))
            continue
        else:
            print("%x has attr %x" % (funcea, attr))
        func_info = {'block': [], 'jmp': [], 'call': []}
        node_record = set()
        function_name = idc.get_func_name(funcea)
        func_info['name'] = function_name
        funcea_name = '%x' % funcea
        # print("func: 0x%x %s" % (funcea, function_name))

        xref_funcptrs = []
        all_blocks = set()
        exit_blocks = []
        link_blocks = set()
        link_blocks.add(funcea)
        function_obj = get_func(funcea)
        func_end = function_obj.end_ea
        flow = FlowChart(function_obj)

        for block in flow:
            func_info['block'].append((block.start_ea, block.end_ea))
            # print("Block: 0x%x" % (block.start_ea))

            get_block_info_arm(funcea, func_end, block, funcs, func_info, blocks_record)

            succ_blocks = list(block.succs())
            for succ_block in succ_blocks:
                func_info['jmp'].append((block.start_ea, succ_block.start_ea))
                link_blocks.add(succ_block.start_ea)
                # print(" Link block: 0x%x" % (succ_block.start_ea))

            all_blocks.add(block.start_ea)

            if len(succ_blocks) == 0 and block.end_ea != function_obj.end_ea:
                # print(" Exit-block: 0x%x" % (block.start_ea))
                exit_blocks.append(block)

        if len(link_blocks) != len(all_blocks):
            switch_blocks = get_switch_block(exit_blocks)
            # print("func: 0x%x %s" % (funcea, function_name))

            if len(switch_blocks) == 1:
                for addr in all_blocks:
                    if addr not in link_blocks:
                        for switch_block in switch_blocks:
                            func_info['jmp'].append((switch_block.start_ea, addr))
                        # print("Unlink block: 0x%x" % (addr))

            elif len(switch_blocks) > 1:
                for switch_block, jmp_ea in switch_blocks.items():
                    # print(" Switch-block: 0x%x, jmp_ea: 0x%x" % (switch_block.start_ea, jmp_ea))
                    sblock_start = switch_block.start_ea
                    if funcea_name not in switch_record:
                        switch_record[funcea_name] = []

                    switch_record[funcea_name].append((sblock_start, jmp_ea))

        cfg_record[funcea_name] = func_info

        block_xrefs_info = {}
        for (bb_addr, ea, func_ptr) in xref_funcptrs:
            if func_ptr not in callees:
                if bb_addr not in block_xrefs_info:
                    block_xrefs_info[bb_addr] = []

                info = (ea, func_ptr, 'func_ptr')
                block_xrefs_info[bb_addr].append(info)

        if len(block_xrefs_info):
            if funcea_name not in blocks_record:
                blocks_record[funcea_name] = {}

            for bb_addr, xref_infos in block_xrefs_info.items():
                blocks_record[funcea_name][bb_addr] = xref_infos


def get_cfg_block_info():


    functions = get_all_functions()

    cfg_record, blocks_record, switch_record = {}, {}, {}

    generate_cfg_arm(functions, cfg_record, blocks_record, switch_record)
    json.dump(cfg_record, open(os.path.join(save_path,file_name + '_cfg.json') , 'w'), indent=4)
    json.dump(blocks_record, open(os.path.join(save_path,file_name + '_block_info.json'), 'w'), indent=4)
    json.dump(switch_record, open(os.path.join(save_path,file_name + '_switch.json'), 'w'), indent=4)

    print('\nExported cfg and block data entries.')





info = get_inf_structure()
if info.is_64bit():
    arch_bits = 64
elif info.is_32bit():
    arch_bits = 32
else:
    raise Exception("Only support 32 or 64 bit arch.")


if info.ostype == idc.OSTYPE_WIN and info.filetype == 11:
    is_windows = True
    is_linux = False

elif info.ostype == 0 and info.filetype == 18:
    is_windows = False
    is_linux = True

else:
    raise Exception("OS type not supported.")

if is_windows and get_imagebase() != 0x0:
    print("Image base has to be 0x0.")
    Exit(0)



extern_seg = None
extern_start = 0
extern_end = 0
text_seg = None
text_start = 0
text_end = 0
plt_seg = None
plt_start = 0
plt_end = 0
got_seg = None
got_start = 0
got_end = 0
idata_seg = None
idata_start = 0
idata_end = 0
data_seg = None
data_start = 0
data_end = 0
vtable_sections = list()
for segment in segments:
    if idc.get_segm_name(segment) == "extern":
        extern_seg = segment
        extern_start = idc.get_segm_start(extern_seg)
        extern_end = idc.get_segm_end(extern_seg)
    elif idc.get_segm_name(segment) == ".text":
        text_seg = segment
        text_start = idc.get_segm_start(text_seg)
        text_end = idc.get_segm_end(text_seg)
    elif idc.get_segm_name(segment) == ".plt":
        plt_seg = segment
        plt_start = idc.get_segm_start(plt_seg)
        plt_end = idc.get_segm_end(plt_seg)
    elif idc.get_segm_name(segment) == ".got":
        got_seg = segment
        got_start = idc.get_segm_start(got_seg)
        got_end = idc.get_segm_end(got_seg)
    elif idc.get_segm_name(segment) == ".idata":
        idata_seg = segment
        idata_start = idc.get_segm_start(idata_seg)
        idata_end = idc.get_segm_end(idata_seg)
    elif idc.get_segm_name(segment) == ".data":
        data_seg = segment
        data_start = idc.get_segm_start(data_seg)
        data_end = idc.get_segm_end(data_seg)
    elif idc.get_segm_name(segment) in vtable_section_names:
        vtable_sections.append(segment)

sections = {}
for segment in segments:
    name = idc.get_segm_name(segment)
    sections[name] = (idc.get_segm_start(segment), idc.get_segm_end(segment))

print(sections)

if '.text' not in sections:
    print("Couldn't found text segment, should custom label!!!")

if '.rodata' not in sections:
    print("Couldn't found rodata segment, should custom label!!!")

if '.data' not in sections:
    print("Couldn't found data segment, should custom label!!!")

if '.bss' not in sections:
    print("Couldn't found bss segment, should custom label!!!")


def main():


    functions = get_all_functions()

    recognise_functions(functions)

    recognise_functions_v2(functions)

    get_cfg_block_info()
main()
