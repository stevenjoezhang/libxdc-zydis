/*
Copyright (c) 2020 Sergej Schumilo, Cornelius Aschermann

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#define bool _Bool
#include "disassembler.h"
#include "cfg.h"
#include "mydbg.h"

#define UNMAPPED_PAGE 0xFFFFFFFFFFFFFFFFULL

#define IGN_MOD_RM			0
#define IGN_OPODE_PREFIX	0
#define MODRM_REG(x)		(x << 3)

bool limit_check(uint64_t bb_start, uint64_t bb_end, uint64_t limit_exit, uint64_t entry) {
	bool covers_exit = (bb_start <= limit_exit) && (limit_exit <= bb_end);
	bool hit_exit = (limit_exit == entry);
	return !covers_exit || hit_exit;
}

#define out_of_bounds(self, addr) ((addr < self->min_addr) || (addr > self->max_addr))

#define in_range(self, addr) (((addr > self->min_addr_0) && (addr < self->max_addr_0)) ||  ((addr > self->min_addr_1) && (addr < self->max_addr_1)) || ((addr > self->min_addr_2) && (addr < self->max_addr_2)) || ((addr > self->min_addr_3) && (addr < self->max_addr_3)))
#define in_range_specific(addr, min, max) ((addr >= min) && (addr < max))

static bool disassembler_iter(disassembler_t* self, ZydisDecoderContext* ctx, uint64_t* address, ZydisDisassembledInstruction *insn, uint64_t* failed_page, ZydisDecoder* current_handle){

	*failed_page = 0xFFFFFFFFFFFFFFFFULL;

	bool success = true;
	size_t code_size = 16;

	uint8_t* code = (uint8_t*)(self->page_cache_fetch_fptr)(self->page_cache_fetch_opaque, *address, &success);

	uint8_t* code_ptr = 0;

	if (code == (void*)UNMAPPED_PAGE || success == false){
		*failed_page = *address;// & 0xFFFFFFFFFFFFF000ULL;
		//printf("FAIL???? (0x%lx) %lx %d\n", *address, code, success);
		return false;
	}

	if ((*address & 0xFFF) >= (0x1000-16)){
		//printf("-------------> Disassemble between pages...%lx (%lx %lx %lx)\n", *address, (*address&0xFFF), (0x1000-16), 0xf-(0xfff-(*address&0xfff)));
		memcpy((void*)self->disassemble_cache, (void*)((uint64_t)code+(0x1000-16)), 16);
		code_ptr = self->disassemble_cache + 0xf-(0xfff-(*address&0xfff));

		code = (uint8_t*)(self->page_cache_fetch_fptr)(self->page_cache_fetch_opaque, *address+0x1000, &success);

		/* broken AF */
		if(success == true){
			memcpy((void*)(self->disassemble_cache+16), (void*)code, 16);
			//code_size = 16;
			*insn = (ZydisDisassembledInstruction)
			{
				.runtime_address = *address
			};
			return ZydisDecoderDecodeInstruction(current_handle, ctx, code_ptr, code_size, &insn->info) == ZYAN_STATUS_SUCCESS;
		}
		else{
			code_size = (0xfff-(*address&0xfff));
			*insn = (ZydisDisassembledInstruction)
			{
				.runtime_address = *address
			};

			if(ZydisDecoderDecodeInstruction(current_handle, ctx, code_ptr, code_size, &insn->info) != ZYAN_STATUS_SUCCESS){
				*failed_page = (*address+0x1000) & 0xFFFFFFFFFFFFF000ULL;

				return false;
			}
			return true;
		}
	}
	else {
		//printf("=> C\n");
		code_ptr = code + (*address&0xFFF);
		*insn = (ZydisDisassembledInstruction)
		{
			.runtime_address = *address
		};

		// DbgPrint("Disassemble...(%lx %x)\n", code_ptr, *code_ptr);
		return ZydisDecoderDecodeInstruction(current_handle, ctx, code_ptr, code_size, &insn->info) == ZYAN_STATUS_SUCCESS;
	}
}


/* ===== kAFL disassembler engine ===== */

static cofi_type opcode_analyzer(ZydisDisassembledInstruction *insn){
	switch (insn->info.meta.category) {
		case ZYDIS_CATEGORY_COND_BR:
			return COFI_TYPE_CONDITIONAL_BRANCH;
		case ZYDIS_CATEGORY_UNCOND_BR:
			switch (insn->info.opcode) {
				case 0xff:
					uint8_t reg_bits = insn->info.raw.modrm.reg << 3;
					if (reg_bits == MODRM_REG(4))
						return COFI_TYPE_INDIRECT_BRANCH;
					else
						return COFI_TYPE_FAR_TRANSFERS;
				default:
					return COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH;
			}
		case ZYDIS_CATEGORY_CALL:
			switch (insn->info.opcode) {
				case 0xe8:
					return COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH;
				case 0x9a:
					return COFI_TYPE_FAR_TRANSFERS;
				case 0xff:
					uint8_t reg_bits = insn->info.raw.modrm.reg << 3;
					if (reg_bits == MODRM_REG(2))
						return COFI_TYPE_INDIRECT_BRANCH;
					else
						return COFI_TYPE_FAR_TRANSFERS;
				case ZYDIS_BRANCH_TYPE_FAR:
					return COFI_TYPE_FAR_TRANSFERS;
				default:
					return COFI_TYPE_INDIRECT_BRANCH;
			}
		case ZYDIS_CATEGORY_RET:
			switch (insn->info.mnemonic) {
				case ZYDIS_MNEMONIC_IRET:
				case ZYDIS_MNEMONIC_IRETD:
				case ZYDIS_MNEMONIC_IRETQ:
					return COFI_TYPE_FAR_TRANSFERS;
				default:
					switch (insn->info.opcode) {
						case 0xca:
						case 0xcb:
							return COFI_TYPE_FAR_TRANSFERS;
						default:
							return COFI_TYPE_NEAR_RET;
					}
			}
		case ZYDIS_CATEGORY_INTERRUPT:
		case ZYDIS_CATEGORY_SYSCALL:
		case ZYDIS_CATEGORY_SYSRET:
			return COFI_TYPE_FAR_TRANSFERS;
		default:
			switch (insn->info.mnemonic) {
				case ZYDIS_MNEMONIC_VMLAUNCH:
				case ZYDIS_MNEMONIC_VMRESUME:
				case ZYDIS_MNEMONIC_UD0:
				case ZYDIS_MNEMONIC_UD1:
				case ZYDIS_MNEMONIC_UD2:
					return COFI_TYPE_FAR_TRANSFERS;
				default:
					return NO_COFI_TYPE;
			}
	}
}

static node_id_t disassemble_bb(disassembler_t* self, uint64_t base_address, uint64_t limit, uint64_t* failed_page, disassembler_mode_t mode){
	// printf("DISASM BB: 0x%llx\n", base_address);
	// printf("x64 handler: %zx\n", self->handle_64);
	ZydisDecoder* current_handle = NULL;

	switch(mode){
		case mode_16:
			current_handle = &self->decoder_16;
			break;
		case mode_32:
			current_handle = &self->decoder_32;
			break;
		case mode_64:
			current_handle = &self->decoder_64;
			break;
		default:
			assert(false);
	}

	ZydisDisassembledInstruction insn;
	ZydisDecoderContext ctx;
	ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
	uint64_t address = base_address;
	node_id_t res_nid = NODE_PAGE_FAULT;
	while(disassembler_iter(self, &ctx, &address, &insn, failed_page, current_handle)){
		address += insn.info.length;
		// printf("insn id: %u; address=0x%p\n", insn.info.mnemonic, (void *)insn.runtime_address);
		// printf("DISASM %s %s\n",insn.info.mnemonic, insn.text);
		if (insn.runtime_address > limit){
			res_nid = disassembler_cfg_add_node(&self->cfg, base_address, insn.runtime_address, OUT_OF_BOUNDS);
			break;
		}

		node_id_t nid = disassembler_cfg_get_node_id(&self->cfg, insn.runtime_address);

		if( nid != NODE_NOT_DEFINED) {
			//printf("DISASM FOUND PREFIX\n");
			//we reached another preexisting basicblock without cofi instruction, copy the data for this node
			res_nid = disassembler_cfg_prefix_node(&self->cfg, base_address, nid);
			break;
		}

		cofi_type type = opcode_analyzer(&insn);

		if( type != NO_COFI_TYPE ){
			//printf("DISASM FOUND COFI\n");
			res_nid = disassembler_cfg_add_node(&self->cfg, base_address, insn.runtime_address, type);

			if (type == COFI_TYPE_CONDITIONAL_BRANCH){
				ZydisDecoderDecodeOperands(current_handle, &ctx, &insn.info, operands, insn.info.operand_count);
				uint64_t target = 0;
				ZydisCalcAbsoluteAddress(&insn.info, &operands[0], insn.runtime_address, &target);
				uint64_t fallthrough = insn.runtime_address + insn.info.length;
				disassembler_cfg_add_br1_addr(&self->cfg, res_nid, target);
				disassembler_cfg_add_br2_addr(&self->cfg, res_nid, fallthrough);
			} else if (type == COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH ){
				ZydisDecoderDecodeOperands(current_handle, &ctx, &insn.info, operands, insn.info.operand_count);
				uint64_t target = 0;
				ZydisCalcAbsoluteAddress(&insn.info, &operands[0], insn.runtime_address, &target);
				disassembler_cfg_add_br1_addr(&self->cfg, res_nid, target);
			} else if (type == COFI_TYPE_INDIRECT_BRANCH || type == COFI_TYPE_NEAR_RET || type == COFI_TYPE_FAR_TRANSFERS) {
				//NOTHING TO BE DONE HERE
			} else {
				assert(false);
			}
			break;
		}
	}
	if(res_nid != NODE_PAGE_FAULT && self->basic_block_callback){
		self->basic_block_callback(self->basic_block_callback_opaque, mode, self->cfg.base_addr[res_nid], self->cfg.cofi_addr[res_nid]);
	}
	return res_nid;
}

disassembler_t* init_disassembler(uint64_t filter[4][2], void* (*page_cache_fetch_fptr)(void*, uint64_t, bool*), void* page_cache_fetch_opaque, uint64_t (*kaslr_address_remapping)(uint64_t), fuzz_bitmap_t* fuzz_bitmap, fuzz_signal_t* fuzz_signal){
	disassembler_t* self = malloc(sizeof(disassembler_t));

	if ( !disassembler_cfg_init(&self->cfg, 0xfffff) )
    {
        disassembler_cfg_destroy(&self->cfg);
        free(self);
        return NULL;
    }

	self->page_cache_fetch_fptr = page_cache_fetch_fptr;
	self->page_cache_fetch_opaque = page_cache_fetch_opaque;
	self->kaslr_address_remapping = kaslr_address_remapping;

	//res->code = code;
	self->infinite_loop_found = false;
	self->debug = false;
	self->signal_overflow = false;

	/* check me */
	self->has_pending_indirect_branch = false;
 	self->pending_indirect_branch_src = 0;

	self->min_addr_0 = filter[0][0];
	self->max_addr_0 = filter[0][1];
	self->min_addr_1 = filter[1][0];
	self->max_addr_1 = filter[1][1];
	self->min_addr_2 = filter[2][0];
	self->max_addr_2 = filter[2][1];
	self->min_addr_3 = filter[3][0];
	self->max_addr_3 = filter[3][1];

	/* fml */
	assert(!in_range_specific(self->min_addr_0, self->min_addr_1, self->max_addr_1));
	assert(!in_range_specific(self->min_addr_0, self->min_addr_2, self->max_addr_2));
	assert(!in_range_specific(self->min_addr_0, self->min_addr_3, self->max_addr_3));
	assert(!in_range_specific(self->max_addr_0-1, self->min_addr_1, self->max_addr_1));
	assert(!in_range_specific(self->max_addr_0-1, self->min_addr_2, self->max_addr_2));
	assert(!in_range_specific(self->max_addr_0-1, self->min_addr_3, self->max_addr_3));

	assert(!in_range_specific(self->min_addr_1, self->min_addr_0, self->max_addr_0));
	assert(!in_range_specific(self->min_addr_1, self->min_addr_2, self->max_addr_2));
	assert(!in_range_specific(self->min_addr_1, self->min_addr_3, self->max_addr_3));
	assert(!in_range_specific(self->max_addr_1-1, self->min_addr_0, self->max_addr_0));
	assert(!in_range_specific(self->max_addr_1-1, self->min_addr_2, self->max_addr_2));
	assert(!in_range_specific(self->max_addr_1-1, self->min_addr_3, self->max_addr_3));

	assert(!in_range_specific(self->min_addr_2, self->min_addr_1, self->max_addr_1));
	assert(!in_range_specific(self->min_addr_2, self->min_addr_0, self->max_addr_0));
	assert(!in_range_specific(self->min_addr_2, self->min_addr_3, self->max_addr_3));
	assert(!in_range_specific(self->max_addr_2-1, self->min_addr_1, self->max_addr_1));
	assert(!in_range_specific(self->max_addr_2-1, self->min_addr_0, self->max_addr_0));
	assert(!in_range_specific(self->max_addr_2-1, self->min_addr_3, self->max_addr_3));

	assert(!in_range_specific(self->min_addr_3, self->min_addr_1, self->max_addr_1));
	assert(!in_range_specific(self->min_addr_3, self->min_addr_2, self->max_addr_2));
	assert(!in_range_specific(self->min_addr_3, self->min_addr_0, self->max_addr_0));
	assert(!in_range_specific(self->max_addr_3-1, self->min_addr_1, self->max_addr_1));
	assert(!in_range_specific(self->max_addr_3-1, self->min_addr_2, self->max_addr_2));
	assert(!in_range_specific(self->max_addr_3-1, self->min_addr_0, self->max_addr_0));


	self->fuzz_bitmap = fuzz_bitmap;
	self->fuzz_signal = fuzz_signal;
	self->trace_cache = trace_cache_new(fuzz_bitmap_get_size(self->fuzz_bitmap));

	memset(self->disassemble_cache, 0x0, 16);

	ZydisDecoderInit(&self->decoder_16, ZYDIS_MACHINE_MODE_LONG_COMPAT_16, ZYDIS_STACK_WIDTH_16);
	ZydisDecoderInit(&self->decoder_32, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
	ZydisDecoderInit(&self->decoder_64, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);

	self->trace_mode = false;

	self->basic_block_callback = NULL;
	self->basic_block_callback_opaque = NULL;
	self->trace_edge_callback = NULL;
	self->trace_edge_callback_opaque = NULL;

	return self;
}

void reset_trace_cache(disassembler_t* self){
	trace_cache_destroy(self->trace_cache);
	self->trace_cache = trace_cache_new(fuzz_bitmap_get_size(self->fuzz_bitmap));
}

void destroy_disassembler(disassembler_t* self){
    if ( !self )
        return;

	trace_cache_destroy(self->trace_cache);
	disassembler_cfg_destroy(&self->cfg);

	free(self);
}

static inline node_id_t get_node(disassembler_t* self, uint64_t entry_point, tnt_cache_t* tnt_cache_state, uint64_t* failed_page, disassembler_mode_t mode){
	node_id_t nid = disassembler_cfg_get_node_id(&self->cfg, entry_point);
	if(nid != NODE_NOT_DEFINED){ return nid; }
	//printf("NEEDS DISASSEMBLY\n");
	if(in_range_specific(entry_point, self->min_addr_0, self->max_addr_0)){
		return disassemble_bb(self, entry_point, self->max_addr_0, failed_page, mode);
	}
	else if(in_range_specific(entry_point, self->min_addr_1, self->max_addr_1)){
		return disassemble_bb(self, entry_point, self->max_addr_1, failed_page, mode);
	}
	else if(in_range_specific(entry_point, self->min_addr_2, self->max_addr_2)){
		return disassemble_bb(self, entry_point, self->max_addr_2, failed_page, mode);
	}
	else if(in_range_specific(entry_point, self->min_addr_3, self->max_addr_3)){
		return disassemble_bb(self, entry_point, self->max_addr_3, failed_page, mode);
	}
	else{
		//printf("OOB FAILED DISASSEBMLY\n");
		*failed_page = 0;
		return NODE_OOB;
	}
}

static inline node_id_t get_node_br1(disassembler_t* self, node_id_t cur_nid, tnt_cache_t* tnt_cache_state, uint64_t* failed_page, disassembler_mode_t mode){
	if(self->cfg.br1[cur_nid].node_id != NODE_NOT_DEFINED){
		return self->cfg.br1[cur_nid].node_id;
	}
	node_id_t next = get_node(self, self->cfg.br1_addr[cur_nid], tnt_cache_state, failed_page, mode);
	disassembler_cfg_add_br1_nid(&self->cfg, cur_nid, next);
	return next;
}

static inline node_id_t get_node_br2(disassembler_t* self, node_id_t cur_nid, tnt_cache_t* tnt_cache_state, uint64_t* failed_page, disassembler_mode_t mode){
	if(self->cfg.br2[cur_nid].node_id != NODE_NOT_DEFINED){
		return self->cfg.br2[cur_nid].node_id;
	}
	node_id_t next = get_node(self, self->cfg.br2_addr[cur_nid], tnt_cache_state, failed_page, mode);
	disassembler_cfg_add_br2_nid(&self->cfg, cur_nid, next);
	return next;
}

static inline void inform_disassembler_target_ip(disassembler_t* self, uint64_t target_ip, bool trace_mode){
  if(self->has_pending_indirect_branch){
		self->has_pending_indirect_branch = false;
		uint64_t from = self->pending_indirect_branch_src;
		uint64_t to = target_ip;
		if(self->kaslr_address_remapping){
			from = (uint64_t)(self->kaslr_address_remapping)(from);
			to = (uint64_t)(self->kaslr_address_remapping)(to);
		}
		if(trace_mode){
			self->trace_edge_callback(self->trace_edge_callback_opaque, from, to);
		}
		if(!trace_mode){
			add_result_tracelet_cache(self->trace_cache->trace_cache, from, to, self->fuzz_bitmap, self->fuzz_signal, &self->signal_overflow);
		}
  }
}

#define MAX_LOOP_COUNT 80000

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
 __attribute__((hot))  static disas_result_t trace_disassembler_loop(disassembler_t* self, uint64_t* entry_point, uint64_t limit, tnt_cache_t* tnt_cache_state, tracelet_cache_t** new_tracelet, trace_cache_key_t* key, uint64_t* failed_page, disassembler_mode_t mode, bool trace_mode){
 //__attribute__((hot)) static bool trace_disassembler_loop(disassembler_t* self, uint64_t* entry_point, uint64_t limit, tnt_cache_t* tnt_cache_state){

	//printf("trace_disassembler_loop %lx \n", *entry_point);

 	static void* dispatch_table[] = {
		&&do_conditional_branch,		// COFI_TYPE_CONDITIONAL_BRANCH,
		&&do_unconditional_branch,		// COFI_TYPE_UNCONDITIONAL_DIRECT_BRANCH
		&&do_indirect_branch,			// COFI_TYPE_INDIRECT_BRANCH
		&&do_near_ret,					// COFI_TYPE_NEAR_RET
		&&do_far_transfers,				// COFI_TYPE_FAR_TRANSFERS
		&&do_failure, 					// COFI_NO_COFI_TYPE
		&&do_out_of_bounds,				// OUT_OF_BOUNDS
		&&do_infinite_loop,
		&&do_page_cache_failed,
	};

	#define BRANCH_CHECK()  dispatch_type = !limit_check(self->cfg.base_addr[nid], self->cfg.cofi_addr[nid], limit, *entry_point) &&\
		 is_empty_tnt_cache(tnt_cache_state) ? OUT_OF_BOUNDS: self->cfg.type[nid];

	#define LOOP_CHECK() dispatch_type = (loop>MAX_LOOP_COUNT) ? INFINITE_LOOP: dispatch_type;

	#define DISPATCH() goto *dispatch_table[dispatch_type]

	int loop = 0;
	uint8_t dispatch_type = 0;
	uint64_t from, to;
	node_id_t nid = NODE_NOT_DEFINED;

	inform_disassembler_target_ip(self, *entry_point, trace_mode);

	if(likely(!trace_mode)){
		reset_tracelet_tmp_cache(self->trace_cache->trace_cache);
	}

	nid = get_node(self, *entry_point, tnt_cache_state, failed_page, mode);

	dispatch_type = self->cfg.type[nid];

	DISPATCH();
	do_conditional_branch:

		//printf("cond branch ");
		if(likely(!trace_mode) && self->trace_cache->trace_cache->cache.tnt_bits == MAX_RESULTS_PER_CACHE-1){
			*entry_point = self->cfg.cofi_addr[nid];
			if(!trace_mode){
				*new_tracelet = new_from_tracelet_cache_tmp(self->trace_cache->trace_cache, true);
			}
			return disas_success;
		}


		switch(process_tnt_cache(tnt_cache_state)){
			case TNT_EMPTY:
				//printf("empty\n");
				if(!trace_mode){
					*new_tracelet = new_from_tracelet_cache_tmp(self->trace_cache->trace_cache, false);
				}
				return disas_tnt_empty;

			case TAKEN:
				// printf("taken 1\n");
				from = self->cfg.cofi_addr[nid];
				to = self->cfg.br1_addr[nid];
				if(self->kaslr_address_remapping){
					from = (uint64_t)(self->kaslr_address_remapping)(from);
					to = (uint64_t)(self->kaslr_address_remapping)(to);
				}
				if(unlikely(trace_mode)){
					self->trace_edge_callback(self->trace_edge_callback_opaque, from, to);
				} else {
					add_result_tracelet_cache(self->trace_cache->trace_cache, from, to, self->fuzz_bitmap, self->fuzz_signal, &self->signal_overflow);
				}
				nid = get_node_br1(self,  nid, tnt_cache_state, failed_page, mode);
				loop = 0;

				BRANCH_CHECK();
				DISPATCH();

			case NOT_TAKEN:
				// printf("not_taken 1\n");
				from = self->cfg.cofi_addr[nid];
				to = self->cfg.br2_addr[nid];
				if(self->kaslr_address_remapping){
					from = (uint64_t)(self->kaslr_address_remapping)(from);
					to = (uint64_t)(self->kaslr_address_remapping)(to);
				}
				if(unlikely(trace_mode)){
					self->trace_edge_callback(self->trace_edge_callback_opaque, from, to);
				} else {
					add_result_tracelet_cache(self->trace_cache->trace_cache, from, to, self->fuzz_bitmap, self->fuzz_signal, &self->signal_overflow);
				}
				nid = get_node_br2(self, nid, tnt_cache_state, failed_page, mode);
				loop = 0;
				BRANCH_CHECK();
				DISPATCH();
}

	do_unconditional_branch:
		//printf("unconditional branch 1\n");
		if(unlikely(trace_mode)){
			self->trace_edge_callback(self->trace_edge_callback_opaque, self->cfg.cofi_addr[nid], self->cfg.br1_addr[nid]);
		}
		nid = get_node_br1(self, nid, tnt_cache_state, failed_page, mode);
		loop++;
		BRANCH_CHECK();
		LOOP_CHECK();
		DISPATCH();

	do_indirect_branch:
	do_near_ret:
		//printf("ret 1\n");

		if(unlikely(trace_mode)){
    		self->has_pending_indirect_branch = true;
    		self->pending_indirect_branch_src = self->cfg.cofi_addr[nid];
			//disassembler_cfg_inspect(&self->cfg, nid);
			//printf("RET with pending src: %lx\n", self->cfg.cofi_addr[nid]);
		} else {
			*new_tracelet = new_from_tracelet_cache_tmp(self->trace_cache->trace_cache, false);
		}

		return disas_tip_pending;

	do_far_transfers:
		//printf("far branch 1\n");
		if(unlikely(trace_mode)){
    		self->has_pending_indirect_branch = true;
    		self->pending_indirect_branch_src = self->cfg.cofi_addr[nid];
		}else {
			*new_tracelet = new_from_tracelet_cache_tmp(self->trace_cache->trace_cache, false);
		}

		return disas_tip_pending;

	do_failure:
		assert(false);

	do_out_of_bounds:
		//printf("OUT OF BOUNDS\n");
		if(likely(!trace_mode)){
			*new_tracelet = new_from_tracelet_cache_tmp(self->trace_cache->trace_cache, false);
		}
		return disas_out_of_bounds;

	do_infinite_loop:
		//printf("inf-loop 1\n");
		if(likely(!trace_mode)){
			*new_tracelet = new_from_tracelet_cache_tmp(self->trace_cache->trace_cache, false);
		}
		return disas_infinite_loop;

	do_page_cache_failed:
		//printf("page_cache_failed 1\n");
		return disas_page_fault;
}
#pragma GCC diagnostic pop

__attribute__((hot)) disas_result_t trace_disassembler(disassembler_t* self, uint64_t entry_point, uint64_t limit, tnt_cache_t* tnt_cache_state, uint64_t* failed_page, disassembler_mode_t mode){

	*failed_page = 0;

	if(unlikely(self->trace_mode)){
			return trace_disassembler_loop(self, &entry_point, limit, tnt_cache_state, NULL, NULL, failed_page, mode, true);
	}

	uint64_t entry_point_tmp = entry_point;
	tracelet_cache_t* new_tracelet = NULL;

	trace_cache_key_t key;

	while(true){
		key.entry = entry_point_tmp;
		key.limit = limit;
		key.tnt_hash = get_tnt_hash(tnt_cache_state);

		new_tracelet = trace_cache_fetch(self->trace_cache, key);
		if(new_tracelet){
			// printf("Trace cache hit\n");
			entry_point_tmp = apply_trace_cache_to_bitmap(new_tracelet, tnt_cache_state, true, self->fuzz_bitmap);

			if(!new_tracelet->cont_exec){
				return disas_success;
			}
		}
		else{
			disas_result_t cont = trace_disassembler_loop(self, &entry_point_tmp, limit, tnt_cache_state, &new_tracelet, &key, failed_page, mode, false);
			if(unlikely(cont == disas_page_fault)){
				/* Early exit at this point. Don't apply preliminary results to the trace cache! */
				return disas_page_fault;
			}
			set_next_entry_addres_tracelet_cache(new_tracelet, entry_point_tmp);
			apply_trace_cache_to_bitmap(new_tracelet, tnt_cache_state, false, self->fuzz_bitmap);

			trace_cache_add(self->trace_cache, key, new_tracelet);
			if(cont != disas_success){
				return disas_success;
			}
		}
	}
	return disas_success;
}
