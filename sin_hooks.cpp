#include "sin_hooks.h"

#include <vector>


namespace sin_hooks
{

uint32_t calculate_relative_addr(void* ptr1, void* ptr2, size_t jump_size)
{
	return (uint32_t)((uint8_t*)ptr2 - ((uint8_t*)ptr1 + jump_size));
}


void init_jump(std::vector<uint8_t>& hook_bytecode,
	void* src_ptr,
	void* dest_memory,
	size_t hook_size)
{
	jump_near_5byte_s near_jump;
	near_jump.relative_addr = calculate_relative_addr(src_ptr, dest_memory, sizeof(near_jump));

	hook_bytecode.insert(hook_bytecode.end(), (uint8_t*)&near_jump, (uint8_t*)(&near_jump) + sizeof(near_jump));
	for (auto i = sizeof(near_jump); i < hook_size; ++i)
		hook_bytecode.push_back(OPCODE_NOP);	// fill by NOPs
}


bool patch_mem(void* dest_memory,
	void* memchunk,
	size_t memchunk_size)
{
	DWORD old_protect_level = PAGE_EXECUTE_READ;
	if (VirtualProtect(dest_memory, memchunk_size, PAGE_EXECUTE_READWRITE, &old_protect_level) == TRUE)
	{
		memcpy(dest_memory, memchunk, memchunk_size);
		return VirtualProtect(dest_memory, memchunk_size, old_protect_level, &old_protect_level) == TRUE;
	}

	return false;
}


bool create_hook(void* src_ptr,
	void* dest_ptr,
	size_t memchunk_size)
{
	std::vector<uint8_t> hook_bytecode;
	init_jump(hook_bytecode, src_ptr, dest_ptr, memchunk_size);

	return patch_mem(src_ptr, hook_bytecode.data(), memchunk_size);
}

}
