#pragma once

/*
* Author: TheCruZ
* Usage:
* Pattern::ScanPatternInExecutableSection(module, "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
* Pattern::ScanPatternInSection(module, ".text", "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
* Pattern::Scan(Start, memLength, "AA BB CC ? ? ? ? ? DD EE ? ? ? ? ? FF")
*/

#ifndef _KERNEL_MODE
#include <Windows.h>
#include <vector>
#include <sstream>
#include <string>
#else
#include <ntdef.h>
#include <ntimage.h>
#endif

//comment this line to remove memory checking (usefull if you don't want to call VirtualQueryEx)
#define CHECK_VALID_MEMORY

struct Pattern
{

	struct sPBy
	{
		bool wildcard;
		unsigned char data;

		sPBy() : wildcard(true), data(0) {} //wildcard byte

		sPBy(const char* bytestr) { //pattern byte (must be 2 chars long)
			data = hexByteToUint8(bytestr);
			wildcard = false;
		}

	private:
		unsigned char hexByteToUint8(const char* bytestr) {
			return (hexCharTooUint8(bytestr[0]) << 4) | hexCharTooUint8(bytestr[1]);
		}

		unsigned char hexCharTooUint8(const char c) {
			if (c >= '0' && c <= '9')
				return (unsigned char)(c - '0');
			if (c >= 'A' && c <= 'F')
				return (unsigned char)(c - 'A' + 10);
			if (c >= 'a' && c <= 'f')
				return (unsigned char)(c - 'a' + 10);
			return 0;
		}
	};
#ifndef _KERNEL_MODE
#ifdef CHECK_VALID_MEMORY

	struct ValidationResult {
		bool valid;
		DWORD64 endOfThisSection;
	};

	static ValidationResult isMemoryValid(void* ptr, size_t size) {

		MEMORY_BASIC_INFORMATION meminfo = { 0 };
		auto ret = VirtualQueryEx(GetCurrentProcess(), ptr, &meminfo, sizeof(meminfo));

		auto regionEnd = ((DWORD64)meminfo.BaseAddress) + meminfo.RegionSize;
		auto checkRangeEnd = ((DWORD64)ptr) + size;

		if (ret <= 0)
			return { false, regionEnd };

		if ((meminfo.State & MEM_COMMIT) == 0)
			return { false, regionEnd };

		if ((meminfo.AllocationProtect & PAGE_GUARD) != 0)
			return { false, regionEnd };

		if ((meminfo.Protect & PAGE_GUARD) != 0)
			return { false, regionEnd };

		if ((meminfo.Protect & PAGE_EXECUTE_READ) == 0 && //VALID PAGES
			(meminfo.Protect & PAGE_EXECUTE_READWRITE) == 0 &&
			(meminfo.Protect & PAGE_READONLY) == 0 &&
			(meminfo.Protect & PAGE_READWRITE) == 0 &&
			(meminfo.Protect & PAGE_EXECUTE_WRITECOPY) == 0 &&
			(meminfo.Protect & PAGE_WRITECOPY) == 0
			)
			return { false, regionEnd };

		if (regionEnd < checkRangeEnd) {

			auto newsize = checkRangeEnd - regionEnd;

			return isMemoryValid((void*)(regionEnd), newsize);
		}

		return { true, regionEnd };
	}
#endif
#endif

	//Always usefull
	PVOID ResolveRelativeAddress(PVOID Instruction, ULONG OffsetOffset, ULONG InstructionSize)
	{
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
		PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
		return ResolvedAddr;
	}

	/*
	* Pattern format wilcard must be "??" or "?" or "?? ?? ??" or "? ? ??" But never "???" for 3 bytes
	* Pattern format: "AA BB CC DD EE ?? FF GG HH"
	* Pattern format alternative: "AABBCCDDEEFF??FFGGHH"
	* Pattern format alternative2: "AA BB CC DD EE ? ? FF GG HH"
	* Pattern format Not supported: "AA BB CC DD EE ???? FF GG HH"
	* Pattern format Not supported: "AABBCCDDEEFF???FFGGHH"
	* SkipCount if pattern is found and skip is >0 then skip to next pattern
	*/
	static DWORD64 Scan(DWORD64 dwStart, size_t dwLength, const char* pattern, size_t skipCount = 0) {

		size_t patternSize = 0;

#ifndef _KERNEL_MODE
		std::vector<sPBy> p;
		std::istringstream iss(pattern);
		std::string w;

		while (iss >> w) {
			if (w.data()[0] == '?') {
				p.push_back(sPBy());
			}
			else if (w.length() == 2 && 
					isxdigit(w.data()[0]) &&
					isxdigit(w.data()[1])) {
				p.push_back(sPBy(w.c_str()));
			}
			else {
				return NULL;
			}
		}

		patternSize = p.size();
#else
		//we don't have vector or istringstream
		auto plen = strlen(pattern);

		sPBy p[256]{}; //max pattern len in kernel mode
		patternSize = 0;

		for (size_t i = 0; i < plen; i++) {
			auto c = pattern[i];
			if (c == ' ') {
				continue;
			}
			else if (c == '?') {
				p[patternSize] = sPBy();
				patternSize++;
				if (i + 1 < plen) {
					if (pattern[i + 1] == '?') {
						++i;
					}
				}
			}
			else if (i + 1 < plen && isxdigit(c) && isxdigit(pattern[i + 1])) {
				p[patternSize] = sPBy(&pattern[i]);
				patternSize++;
				i++;
			}
			else {
				return NULL;
			}
			if (patternSize == 256) { //too big pattern
				return NULL;
			}
		}
#endif

#ifndef _KERNEL_MODE
#ifdef CHECK_VALID_MEMORY
		auto vCheck = isMemoryValid((void*)dwStart, patternSize);
#endif
#endif
		for (DWORD64 i = 0; i < dwLength; i++) {
			UINT8* lpCurrentByte = (UINT8*)(dwStart + i);
#ifndef _KERNEL_MODE
#ifdef CHECK_VALID_MEMORY
			if ((DWORD64)lpCurrentByte + patternSize > vCheck.endOfThisSection || !vCheck.valid) {
				vCheck = isMemoryValid(lpCurrentByte, patternSize);
				if (!vCheck.valid) {
					i += vCheck.endOfThisSection - (DWORD64)lpCurrentByte; //skip page
					--i; // i will be increased in continue
					continue;
				}
			}
#endif
#endif

			bool found = true;
			for (size_t ps = 0; ps < patternSize; ps++) {
				if (p[ps].wildcard == false && lpCurrentByte[ps] != p[ps].data) {
					found = false;
					break;
				}
			}

			if (found && skipCount == 0) {
				return (DWORD64)lpCurrentByte;
			}
			else if (found && skipCount > 0) {
				skipCount--;
			}
		}

		return NULL;
	}

	static PIMAGE_SECTION_HEADER GetSectionByName(const void* module, const char* sectionName) {
		auto dosHeader = (PIMAGE_DOS_HEADER)module;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((DWORD64)dosHeader + dosHeader->e_lfanew);
		auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
		auto searchlen = strlen(sectionName);
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if (searchlen == 8 && memcmp(sectionHeader->Name, sectionName, searchlen) == 0) {
				return sectionHeader;
			}
			else if (strcmp((char*)sectionHeader->Name, sectionName) == 0) {
				return sectionHeader;
			}
			sectionHeader++;
		}
		return 0;
	}

	/*
	* Pattern format wilcard must be "??" or "?" or "?? ?? ??" or "? ? ??" But never "???" for 3 bytes
	* Pattern format: "AA BB CC DD EE ?? FF GG HH"
	* Pattern format alternative: "AABBCCDDEEFF??FFGGHH"
	* Pattern format alternative2: "AA BB CC DD EE ? ? FF GG HH"
	* Pattern format Not supported: "AA BB CC DD EE ???? FF GG HH"
	* Pattern format Not supported: "AABBCCDDEEFF???FFGGHH"
	* SkipCount if pattern is found and skip is >0 then skip to next pattern
	*/
	static DWORD64 ScanPatternInSection(const void* module, const char* sectionName, const char* pattern, size_t skipCount = 0) {
		auto section = GetSectionByName(module, sectionName);
		if (!section)
			return 0;
		auto sectionSize = section->Misc.VirtualSize;
		auto sectionAddress = (DWORD64)section->VirtualAddress + (DWORD64)module;
		return Scan(sectionAddress, sectionSize, pattern, skipCount);
	}

	/*
	* Pattern format wilcard must be "??" or "?" or "?? ?? ??" or "? ? ??" But never "???" for 3 bytes
	* Pattern format: "AA BB CC DD EE ?? FF GG HH"
	* Pattern format alternative: "AABBCCDDEEFF??FFGGHH"
	* Pattern format alternative2: "AA BB CC DD EE ? ? FF GG HH"
	* Pattern format Not supported: "AA BB CC DD EE ???? FF GG HH"
	* Pattern format Not supported: "AABBCCDDEEFF???FFGGHH"
	* SkipCount if pattern is found and skip is >0 then skip to next pattern in executable section, all skip needs to be in same section
	*/
	static DWORD64 ScanPatternInExecutableSection(const void* module, const char* pattern, size_t skipCount = 0) {
		auto dosHeader = (PIMAGE_DOS_HEADER)module;
		auto ntHeaders = (PIMAGE_NT_HEADERS)((DWORD64)dosHeader + dosHeader->e_lfanew);
		auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
		for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
			if ((sectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 &&
				(sectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE) == 0) {
				auto sectionSize = sectionHeader->Misc.VirtualSize;
				auto sectionAddress = (DWORD64)sectionHeader->VirtualAddress + (DWORD64)module;
				auto result = Scan(sectionAddress, sectionSize, pattern, skipCount);
				if (result != 0) {
					return result;
				}
			}
			sectionHeader++;
		}
	}
};