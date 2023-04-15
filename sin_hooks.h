#pragma once

/*
	author: Singularity, type gravioz@gmail.com
	01.03.2020

	examples:

	// EXAMPLE #1. first type hook. naked with own control
	ptrdiff_t g_fake_func_original_addr = 0;
	const char* hooked_message = "hooked";
	const char* hooked_message2 = "new title";
	void __stdcall print_message()
	{
		printf("hooked\n");
	}
	__declspec(naked) void fake_func()
	{
		_asm
		{
			push	ebp
			mov		ebp, esp
			pushad

			; own code begin

			lea			eax, [esp + 0x2C]; params of Original func

			push	hooked_message; text
			push	hooked_message2; title
			pop		edx
			pop		ecx
			mov[eax], ecx; change params context
			mov[eax + 4], edx

			call	print_message

			; own code end

			popad
			mov		esp, ebp
			pop		ebp

			; original code
			mov		edi, edi
			push	ebp
			mov		ebp, esp
			//push	0

			; return to original
			push g_fake_func_original_addr
			ret
		}
	}
	int main(void)
	{
		size_t hook_size = 5;
		ptrdiff_t ptr = (ptrdiff_t)&MessageBoxA;
		g_fake_func_original_addr = ptr + hook_size;
		MessageBoxA(0, "original func", "original func", MB_OK | MB_ICONINFORMATION);
		create_hook(MessageBoxA, fake_func, hook_size);
		MessageBoxA(0, "original func", "original func", MB_OK | MB_ICONINFORMATION);

		return 0;
	}

	// EXAMPLE #2. second type hook. function-level hooks
	typedef HANDLE(WINAPI fncPtr_CreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
	sin_hook_c<fncPtr_CreateFileW> g_CreateFileWHook;
	HANDLE WINAPI hooked_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurity, DWORD dwCreationDisp, DWORD dwFlags, HANDLE hTemplate)
	{
		printf("CreateFileW hooked\n");
		return g_CreateFileWHook.original_call
		(
			lpFileName,
			dwDesiredAccess,
			dwShareMode,
			lpSecurity,
			dwCreationDisp,
			dwFlags,
			hTemplate
		);
	}
	int main()
	{
		g_CreateFileWHook.set_target_func(CreateFileW);
		g_CreateFileWHook.set_fake_func(hooked_CreateFileW);
		g_CreateFileWHook.set_stdcall_hook();

		// test
		{
			HANDLE hFile = CreateFileW(L"test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			CloseHandle(hFile);
		}

		return 0;
	}
*/

#include <Windows.h>
#include <stdint.h>
#include <string>


// debug macros
//#define DEBUG_OUTPUT_SIN_HOOK_ENABLE_CODE


// useful macros
#define DECLARE_WINAPI_SIN_HOOK(API_FUNC, FUNC_RETURN_TYPE, ...)						\
	typedef FUNC_RETURN_TYPE (WINAPI fncPtr_ ## API_FUNC)(__VA_ARGS__);					\
	sin_hooks::sin_hook_c<fncPtr_ ## API_FUNC> g_ ## API_FUNC ## Hook("" # API_FUNC);	\
	FUNC_RETURN_TYPE WINAPI hooked_ ## API_FUNC(__VA_ARGS__)

#define DECLARE_WINAPI_SIN_HOOK_NAMED(API_FUNC, HOOK_NAME_STR, FUNC_RETURN_TYPE, ...)	\
	typedef FUNC_RETURN_TYPE (WINAPI fncPtr_ ## API_FUNC)(__VA_ARGS__);					\
	sin_hooks::sin_hook_c<fncPtr_ ## API_FUNC> g_ ## API_FUNC ## Hook(HOOK_NAME_STR);	\
	FUNC_RETURN_TYPE WINAPI hooked_ ## API_FUNC(__VA_ARGS__)

#define SIN_HOOK_ORIGINAL_CALL(API_FUNC, ...)											\
	g_ ## API_FUNC ## Hook.original_call(__VA_ARGS__);

#define SIN_HOOK_ENABLE_HOOK(API_FUNC)													\
	g_ ## API_FUNC ## Hook.set_target_func(API_FUNC);									\
	g_ ## API_FUNC ## Hook.set_fake_func(hooked_ ## API_FUNC);							\
	sin_hook_status = g_ ## API_FUNC ## Hook.set_hook();


// service macros
#define		OPCODE_PUSH_IMM8		0x6A
#define		OPCODE_PUSH_IMM32		0x68
#define		OPCODE_JMP_RELATIVE		0xE9
#define		OPCODE_NOP				0x90
#define		OPCODE_MOV_EAX			0xB8
#define		OPCODE_MOV_ECX			0xB9
#define		OPCODE_JMP_EAX			0xE0FF
#define		OPCODE_CALL_EAX			0xD1FF
#define		OPCODE_POP_EAX			0x58
#define		OPCODE_CALL_RELATIVE	0xE8


#define get_eip_value(_eip_value)		\
{										\
	__asm								\
	{									\
		jmp real_code					\
										\
		get_eip:						\
			mov ecx, [esp]				\
			ret							\
										\
		real_code:						\
			call get_eip				\
			sub ecx, 17					\
			mov _eip_value, eax			\
	}									\
}


namespace sin_hooks
{

// opcodes
enum e_sinhook_opcodes
{
	opcode_unknown							= 0,
	opcode_supported_prologue_opcodes_begin	= 1,	// start mark of supported list of prologue opcodes. only commands between 2 marks are possible in prologue

	opcode_push_imm8,
	opcode_push_imm32,
	opcode_jmp_far32,
	opcode_sub_rsp,
	opcode_call_relative,

	opcode_supported_prologue_opcodes_end,			// end mark of supported list of prologue opcodes

	opcode_jmp_relative,

};


// common structures
#pragma pack(push, 1)
struct jump_near_5byte_s
{
	uint8_t opcode				= OPCODE_JMP_RELATIVE;
	uint32_t relative_addr		= 0;
};
struct jump_x64_near_6byte_s
{
	uint16_t opcode				= 0x25FF;
	uint32_t relative_addr		= 0;
};
struct jump_absolute_7byte_s
{
	/*
		pseudo-code:
		B8 E0 FF B7 00       mov         eax,0B7FFE0h
		FF E0                jmp         eax
	*/
	uint8_t mov_eax_opcode		= OPCODE_MOV_EAX;
	uint32_t mov_eax_operand	= 0;				// absolute addr
	uint16_t jmp_eax_opcode		= OPCODE_JMP_EAX;
};
struct call_event_bytecode_s
{
	uint8_t mov_ecx_opcode		= OPCODE_MOV_ECX;
	uint32_t mov_ecx_operand	= 0x00;

	uint8_t push_opcode			= OPCODE_PUSH_IMM32;
	uint32_t push_operand		= 0x00;

	uint16_t call_eax			= OPCODE_CALL_EAX;

	jump_absolute_7byte_s fake_jump;

#if 0	// only if hook event function is cdecl
	uint8_t	pop_eax				= OPCODE_POP_EAX; // restore original esp pointer
#endif
};
#pragma pack(pop)


// prototypes
uint32_t calculate_relative_addr(void* ptr1, void* ptr2, size_t jump_size);
bool patch_mem(void* dest_memory, void* memchunk, size_t memchunk_size);
bool create_hook(void* src_ptr, void* dest_ptr, size_t memchunk_size);


// standard signatures
static const uint8_t stdcall_signature[5]	= { 0x8B, 0xFF, 0x55, 0x8B, 0xEC };


// local functions
static bool g_sinhooks_enable_events = false;
typedef void(__stdcall *hook_event_t)(const char*);
static void enable_global_sinhooks_events(bool enable = true)
{
	g_sinhooks_enable_events = enable;
}


static void __stdcall sinhooks_hook_event(const char* hook_name) {}
static hook_event_t g_global_sinhook_event_function = sinhooks_hook_event;
static void set_global_sinhook_event_function(hook_event_t event_function_ptr)
{
	g_global_sinhook_event_function = event_function_ptr;
}

#pragma optimize("", off)

// function-level hooks
template <typename FnT>
class sin_hook_c			// non virtual
{
public:
	sin_hook_c(const std::string& hook_name = std::string())
		: m_hook_name(hook_name)
	{
		SYSTEM_INFO system_info;
		GetSystemInfo(&system_info);
		m_page_size = system_info.dwPageSize;

#ifdef DEBUG_OUTPUT_SIN_HOOK_ENABLE_CODE
		char buf[256] = {};
		sprintf_s(buf, "SIN_HOOK_ENABLE_HOOK(%s); _ASSERT(sin_hook_status);\n", hook_name.c_str());
		OutputDebugStringA(buf);
#endif
	}


	~sin_hook_c()
	{
		remove_hook();
	}


	void set_target_func(FnT func_ptr)
	{
		m_target_fptr = func_ptr;
	}


	void set_fake_func(FnT func_ptr)
	{
		m_fake_fptr = func_ptr;
	}


#ifdef _M_IX86
	bool set_hook()
	{
		if (is_hooked())
			return true;

		m_trampoline_size = 0;

		m_enable_events = g_sinhooks_enable_events;
		m_hook_event_function_ptr = g_global_sinhook_event_function;

		bool no_trampoline_backjump = false;

		// check and correct pointers
		m_fake_fptr = get_real_function_pointer(m_fake_fptr);
		m_target_fptr = get_real_function_pointer(m_target_fptr);

		// check for standard stdcall signature
		if (memcmp(m_target_fptr, stdcall_signature, sizeof(stdcall_signature)) != 0)
		{
			// no standard prologue - check target code bytecode length
			e_sinhook_opcodes targetmem_opcode;
			uint32_t targetmem_opcode_length = determine_opcode_length((uint8_t*)m_target_fptr, targetmem_opcode);

			if (targetmem_opcode == opcode_jmp_far32)
			{
				// if target memory point to jump instruction - we need just replace jump code to our hook-jump and no need to jump back to original code
				m_hook_size = targetmem_opcode_length;
				no_trampoline_backjump = true;
			}
#if 1
			//else if (targetmem_opcode == opcode_jmp_relative)
			else if (targetmem_opcode == opcode_call_relative)
			{
				m_recompile_target_code = true;
			}
#endif
			else if (targetmem_opcode == opcode_push_imm32)
			{
				// standard hook code
			}
			else // non standard prologue code
			{
				ptrdiff_t bytecode_iterator = (ptrdiff_t)m_target_fptr;

				size_t prologue_bytecode_size = 0;

				// search for suitable prologue
				while (true)
				{
					prologue_bytecode_size += targetmem_opcode_length;

					if (targetmem_opcode <= opcode_supported_prologue_opcodes_begin
						|| targetmem_opcode >= opcode_supported_prologue_opcodes_end)
					{
						// unsupported prologue
						return false;
					}

					// if we reach minimal prologue size - finish check
					if (prologue_bytecode_size >= m_minimal_prologue_size)
					{
						if (targetmem_opcode == opcode_jmp_far32)	// if last detected command is jump - no trampoline backjump is needed
							no_trampoline_backjump = true;

						m_hook_size = prologue_bytecode_size;
						break;
					}

					bytecode_iterator += targetmem_opcode;
					targetmem_opcode_length = determine_opcode_length((uint8_t*)bytecode_iterator, targetmem_opcode);
				}
			}
		}

		// original_return_addr is point to after our hook
		m_original_return_addr = (decltype(m_original_return_addr))m_target_fptr + m_hook_size;

		// allocate necessary mem to store events-code segment and trampoline
		m_mem_block = (decltype(m_mem_block))VirtualAlloc(nullptr, m_page_size, MEM_COMMIT, PAGE_READWRITE);
		memset(m_mem_block, OPCODE_NOP, m_page_size);

		// trampoline by default points to start of mem_block
		m_trampoline_code_ptr = m_mem_block;

		DWORD old_protect_level;
		if (VirtualProtect(m_mem_block,
				m_page_size,
				PAGE_READWRITE,
				&old_protect_level) == TRUE)
		{
			if (m_enable_events)
			{
				/*
					if events enabled, then fire hook_event every time when hook occurs.
					algorithm:
					code segment looks like this:
					B9 70 57 40 01       mov         ecx,1405770h	- pointer to event procedure
					68 7C E4 48 01       push        148E47Ch		- pointer to hook_name param
					FF D1                call        ecx			- fire event
					B8 30 09 3F 01       mov         eax,13F0930h	- pointer to fake function
					FF E0                jmp         eax			- jump to fake function

					in this case m_fake_entry_point points to call_event code segment
				*/
				ptrdiff_t hook_event_ptr = (decltype(hook_event_ptr))m_hook_event_function_ptr;
				ptrdiff_t hook_name_ptr = (decltype(hook_name_ptr))m_hook_name.c_str();

				m_call_event_code_ptr = m_mem_block;
				call_event_bytecode_s* const call_event_bytecode = (decltype(call_event_bytecode))m_call_event_code_ptr;
				{
					call_event_bytecode->mov_ecx_opcode				= OPCODE_MOV_ECX;
					call_event_bytecode->mov_ecx_operand			= (decltype(call_event_bytecode->mov_ecx_operand))hook_event_ptr;
					call_event_bytecode->push_opcode				= OPCODE_PUSH_IMM32;
					call_event_bytecode->push_operand				= (decltype(call_event_bytecode->push_operand))hook_name_ptr;
					call_event_bytecode->call_eax					= OPCODE_CALL_EAX;
					call_event_bytecode->fake_jump.mov_eax_opcode	= OPCODE_MOV_EAX;
					call_event_bytecode->fake_jump.mov_eax_operand	= (decltype(call_event_bytecode->fake_jump.mov_eax_operand))m_fake_fptr;
					call_event_bytecode->fake_jump.jmp_eax_opcode	= OPCODE_JMP_EAX;
#if 0	// only if hook event function is cdecl
					call_event_bytecode->pop_eax					= OPCODE_POP_EAX; // clean stack
#endif
				}

				m_trampoline_code_ptr += sizeof(call_event_bytecode_s);

				m_fake_entry_point = (decltype(m_fake_entry_point))m_call_event_code_ptr;
			}
			else
			{
				m_fake_entry_point = m_fake_fptr;
			}

#if 1
			// copy original code to our trampoline memory block... or recompile original code
			if (m_recompile_target_code)
			{
				if (*(uint8_t*)m_target_fptr == OPCODE_JMP_RELATIVE)
				{
					auto absolute_target_addr = x86_near_addr_to_absolute(m_target_fptr);

					jump_near_5byte_s* recompiled_jump = (decltype(recompiled_jump))m_trampoline_code_ptr;
					recompiled_jump->opcode			= OPCODE_JMP_RELATIVE;
					recompiled_jump->relative_addr	= calculate_relative_addr(m_trampoline_code_ptr, absolute_target_addr, sizeof(jump_near_5byte_s));

					m_original_code_memory = new uint8_t[m_hook_size];
					memcpy((void*)m_original_code_memory, m_target_fptr, m_hook_size);
				}
				else if (*(uint8_t*)m_target_fptr == OPCODE_CALL_RELATIVE)
				{
					auto absolute_target_addr = x86_near_addr_to_absolute(m_target_fptr);

					jump_near_5byte_s* recompiled_jump = (decltype(recompiled_jump))m_trampoline_code_ptr;
					recompiled_jump->opcode = OPCODE_CALL_RELATIVE;
					recompiled_jump->relative_addr = calculate_relative_addr(m_trampoline_code_ptr, absolute_target_addr, sizeof(jump_near_5byte_s));

					m_original_code_memory = new uint8_t[m_hook_size];
					memcpy((void*)m_original_code_memory, m_target_fptr, m_hook_size);
				}
				else
				{
					return false;
				}
			}
			else
#endif
			{
				memcpy((void*)m_trampoline_code_ptr, m_target_fptr, m_hook_size);
			}

			m_trampoline_size += m_hook_size;

			// make backjump only if needs
			if (!no_trampoline_backjump)
			{
				jump_near_5byte_s orig_jump_bytecode;
				orig_jump_bytecode.relative_addr =
					calculate_relative_addr
					(
						(void*)m_trampoline_code_ptr,
						(void*)m_original_return_addr,
						m_minimal_prologue_size + m_hook_size
					);

				memcpy
				(
					(void*)(m_trampoline_code_ptr + m_hook_size),
					(const void*)&orig_jump_bytecode,
					m_hook_size
				);
				m_trampoline_size += sizeof(orig_jump_bytecode);
			}

			VirtualProtect(m_mem_block, m_page_size, PAGE_EXECUTE_READ, &old_protect_level);

			original_call = (decltype(original_call))m_trampoline_code_ptr;

			return m_is_hooked = create_hook(m_target_fptr, m_fake_entry_point, m_hook_size);
		}

		return false;
	}
#else
	bool set_hook()
	{
		if (is_hooked())
			return true;

		m_trampoline_size = 0;

		m_enable_events = g_sinhooks_enable_events;
		m_hook_event_function_ptr = g_global_sinhook_event_function;

		bool no_trampoline_backjump = false;

		// check and correct pointers
		m_fake_fptr = get_real_function_pointer(m_fake_fptr);
		m_target_fptr = get_real_function_pointer(m_target_fptr);

		// check prologue
		{
			// no standard prologue - check target code bytecode length
			e_sinhook_opcodes targetmem_opcode;
			uint32_t targetmem_opcode_length = determine_opcode_length((uint8_t*)m_target_fptr, targetmem_opcode);

			if (targetmem_opcode == opcode_jmp_far32)
			{
				// if target memory point to jump instruction - we need just replace jump code to our hook-jump and no need to jump back to original code
				m_hook_size = targetmem_opcode_length;
				no_trampoline_backjump = true;
			}
#if 0
			else if (targetmem_opcode == opcode_jmp_relative)
			{
				m_recompile_target_code = true;
			}
#endif
			else if (targetmem_opcode == opcode_push_imm32)
			{
				// standard hook code
			}
			else // non standard prologue code
			{
				ptrdiff_t bytecode_iterator = (ptrdiff_t)m_target_fptr;

				size_t prologue_bytecode_size = 0;

				// search for suitable prologue
				while (true)
				{
					prologue_bytecode_size += targetmem_opcode_length;

					if (targetmem_opcode <= opcode_supported_prologue_opcodes_begin
						|| targetmem_opcode >= opcode_supported_prologue_opcodes_end)
					{
						// unsupported prologue
						return false;
					}

					// if we reach minimal prologue size - finish check
					if (prologue_bytecode_size >= m_minimal_prologue_size)
					{
						if (targetmem_opcode == opcode_jmp_far32)	// if last detected command is jump - no trampoline backjump is needed
							no_trampoline_backjump = true;

						m_hook_size = prologue_bytecode_size;
						break;
					}

					bytecode_iterator += targetmem_opcode;
					targetmem_opcode_length = determine_opcode_length((uint8_t*)bytecode_iterator, targetmem_opcode);
				}
			}
		}

		return true;
	}
#endif


	void remove_hook()
	{
		if (is_hooked())
		{
			// return original code
			_ASSERT(m_trampoline_code_ptr != nullptr);
			patch_mem(m_target_fptr, m_trampoline_code_ptr, m_hook_size);
			m_is_hooked = false;
		}

		// free trampoline memory at last
		if (m_mem_block)
		{
			VirtualFree(m_mem_block, 0, MEM_RELEASE);
			m_mem_block = nullptr;
		}
	}


	const std::string& get_hook_name() const
	{
		return m_hook_name;
	}


	bool is_hooked() const
	{
		return m_is_hooked;
	}


	void set_event_function(hook_event_t event_function_ptr)
	{
		m_hook_event_function_ptr = event_function_ptr;
	}


	FnT* original_call						= nullptr;

public:
	FnT* get_real_function_pointer(FnT* memptr)
	{
		uint8_t* memptr_casted = (decltype(memptr_casted))memptr;

		if (memptr_casted[0] == OPCODE_JMP_RELATIVE)
		{
			return x86_near_addr_to_absolute(memptr);
		}

#ifdef _WIN64
		if (memptr_casted[0] == 0xFF && memptr_casted[1] == 0x25)		// jmp far
		{
			return x64_near_addr_to_absolute(memptr);
		}
#endif
		return memptr;
	}


	FnT* x64_near_addr_to_absolute(FnT* memptr)
	{
		jump_x64_near_6byte_s* jump_near = (decltype(jump_near))memptr;

		ptrdiff_t absolute_addr = (decltype(absolute_addr))memptr
			+ jump_near->relative_addr
			+ sizeof(jump_x64_near_6byte_s);

		return (FnT*)(*(decltype(absolute_addr)*)absolute_addr);
	}


	FnT* x86_near_addr_to_absolute(FnT* memptr)
	{
		jump_near_5byte_s* jump_near = (decltype(jump_near))memptr;

		ptrdiff_t absolute_addr = (decltype(absolute_addr))memptr
			+ jump_near->relative_addr
			+ sizeof(jump_near_5byte_s);

		return (FnT*)absolute_addr;
	}


	uint32_t determine_opcode_length(uint8_t* memptr, e_sinhook_opcodes& opcode)//, ptrdiff_t& addr)
	{
		opcode = opcode_unknown;

		// cases

		// x64
		if (memptr[0] == 0x48 && memptr[1] == 0x83 && memptr[2] == 0xEC)
		{
			opcode = opcode_sub_rsp;
			return 4;
		}

		// x86
		if (memptr[0] == 0xFF && memptr[1] == 0x25)		// jmp far
		{
			// 76E73EB0 FF 25 0C 10 ED 76    jmp         dword ptr ds:[76ED100Ch]

			opcode = opcode_jmp_far32;
			return 6;
		}

		if (memptr[0] == OPCODE_PUSH_IMM32)
		{
			opcode = opcode_push_imm32;
			return 5;
		}

		if (memptr[0] == OPCODE_JMP_RELATIVE)
		{
			opcode = opcode_jmp_relative;
			return 5;
		}

		if (memptr[0] == OPCODE_PUSH_IMM8)
		{
			opcode = opcode_push_imm8;
			return 2;
		}

		if (memptr[0] == OPCODE_CALL_RELATIVE)
		{
			opcode = opcode_call_relative;
			return 5;
		}

		return 0;
	}

private:
	DWORD m_page_size						= 4096;	// 4Kb page by default

	FnT* m_target_fptr						= nullptr;
	FnT* m_fake_fptr						= nullptr;

	uint8_t* m_mem_block					= nullptr;
	uint8_t* m_trampoline_code_ptr			= nullptr;
	uint8_t* m_call_event_code_ptr			= nullptr;

#if 1
	//uint8_t* m_recompile_code_memory		= nullptr;
	uint8_t* m_original_code_memory			= nullptr;
	bool m_recompile_target_code			= false;
#endif

	size_t m_trampoline_size				= 0;

	ptrdiff_t m_original_return_addr		= 0;

	FnT* m_fake_entry_point					= nullptr;

	const size_t m_minimal_prologue_size	= 5;
	size_t m_hook_size						= sizeof(jump_near_5byte_s);	// size can be changed

	std::string m_hook_name;
	bool m_is_hooked						= false;

	bool m_enable_events					= false;
	hook_event_t m_hook_event_function_ptr	= g_global_sinhook_event_function;
};

#pragma optimize("", on)

}
