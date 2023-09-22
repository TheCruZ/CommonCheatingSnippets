#pragma once

#ifndef CALL_SPOOF_HPP
#define CALL_SPOOF_HPP

#pragma warning(disable: 4083)
#pragma warning(disable: 4005)

#include <xtr1common>

#pragma warning(default: 4083)
#pragma warning(default: 4005)

/*
* Author: namazso
*
* Usage:
* spoof_call(simulated_return_address, function_to_call, arg1, arg2...);
* "simulated_return_address" needs to be "jmp rbx" and can be modified to different jump type changing it on spoof.masm
* to enable spoof.masm compilation you have to:
*    - go to right side and right-click on your project name, from the menu navigate to "Build Dependencies" -> Build Customizations. and enable masm
*    - verify that masm file is enabled in the compilation
*        - go to right side and right-click on your spoof.masm file -> Properties -> "Type of element" -> "Microsoft Macro Assembler"
*
*/


/*
*	Variable amount of arguments for shellcodes moving our extra parameter to the stack
*	https://www.unknowncheats.me/forum/c-and-c-/267587-comfy-direct-syscall-caller-x64.html
*/
namespace detail
{
	extern "C" void* _spoofer_stub();

	template <typename Ret, typename... Args>
	static inline auto shellcode_stub_helper(
		const void* shell,
		Args... args
	) -> Ret
	{
		auto fn = (Ret(*)(Args...))(shell);
		return fn(args...);
	}

	template <size_t Argc, typename>
	struct argument_remapper
	{
		// At least 5 params
		template<
			typename Ret,
			typename First,
			typename Second,
			typename Third,
			typename Fourth,
			typename... Pack
		>
		static auto do_call(
			const void* shell,
			void* shell_param,
			First first,
			Second second,
			Third third,
			Fourth fourth,
			Pack... pack
		) -> Ret
		{
			return shellcode_stub_helper<
				Ret,
				First,
				Second,
				Third,
				Fourth,
				void*,
				void*,
				Pack...
			>(
				shell,
				first,
				second,
				third,
				fourth,
				shell_param,
				nullptr,
				pack...
			);
		}
	};

	template <size_t Argc>
	struct argument_remapper<Argc, std::enable_if_t<Argc <= 4>>
	{
		// 4 or less params
		template<
			typename Ret,
			typename First = void*,
			typename Second = void*,
			typename Third = void*,
			typename Fourth = void*
		>
		static auto do_call(
			const void* shell,
			void* shell_param,
			First first = First{},
			Second second = Second{},
			Third third = Third{},
			Fourth fourth = Fourth{}
		) -> Ret
		{
			return shellcode_stub_helper<
				Ret,
				First,
				Second,
				Third,
				Fourth,
				void*,
				void*
			>(
				shell,
				first,
				second,
				third,
				fourth,
				shell_param,
				nullptr
			);
		}
	};
}

/*
* https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html
* Spoofs the return address on the stack to the trampoline "jmp rbx" that jumps back to the original return address
*/
template <typename Ret, typename... Args>
static inline auto spoof_call(
	const void* trampoline,
	Ret(*fn)(Args...),
	Args... args
) -> Ret
{
	struct shell_params
	{
		const void* trampoline;
		void* function;
		void* rbx;
	};

	shell_params p{ trampoline, reinterpret_cast<void*>(fn) };
	using mapper = detail::argument_remapper<sizeof...(Args), void>;
	return mapper::template do_call<Ret, Args...>((const void*)&detail::_spoofer_stub, &p, args...);
}

#endif