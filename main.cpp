/**
* Author: Felipe Alfonso
* E-mail: felipe@bitnenfer.com
*/

#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <new>
#include <inttypes.h>

// This will pause the execution for each step
#define ALLOW_WAIT 1

// Log to stdout and VS output window
#define ALLOW_LOG 1

#if _DEBUG
void PrintErrorMessage(uint32_t dwErr)
{

	WCHAR   wszMsgBuff[512];  // Buffer for text.

	DWORD   dwChars;  // Number of chars returned.

	// Try to get the message from the system errors.
	dwChars = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL,
		dwErr,
		0,
		wszMsgBuff,
		512,
		NULL);

	if (0 == dwChars)
	{
		// The error code did not exist in the system errors.
		// Try Ntdsbmsg.dll for the error code.

		HINSTANCE hInst;

		// Load the library.
		hInst = LoadLibrary(L"Ntdsbmsg.dll");
		if (NULL == hInst)
		{
			printf("cannot load Ntdsbmsg.dll");
			exit(1);  // Could 'return' instead of 'exit'.
		}

		// Try getting message text from ntdsbmsg.
		dwChars = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE |
			FORMAT_MESSAGE_IGNORE_INSERTS,
			hInst,
			dwErr,
			0,
			wszMsgBuff,
			512,
			NULL);

		// Free the library.
		FreeLibrary(hInst);

	}

	// Display the error message, or generic text if not found.
	printf("Error value: %d Message: %ws",
		dwErr,
		dwChars ? wszMsgBuff : L"Error message not found.");

	OutputDebugStringW(L"Error: ");
	OutputDebugStringW(dwChars ? wszMsgBuff : L"Error message not found.");
	OutputDebugStringW(L"");
}
void CheckForError()
{
	uint32_t ErrorCode = GetLastError();
	if (ErrorCode != S_OK)
	{
		PrintErrorMessage(ErrorCode);
	}
}
#define ASSERT(x) if (!(x)) { CheckForError(); __debugbreak();  ExitProcess(1); }
#else
#define ASSERT(x) (x)
#endif

#include <intrin.h>
#include <stdint.h>

namespace mem
{
	namespace utility
	{
		template<typename T = void>
		__forceinline T* OffsetPtr(T* Ptr, int64_t Offset)
		{
			return reinterpret_cast<T*>(reinterpret_cast<intptr_t>(Ptr) + Offset);
		}

		template<typename T>
		__forceinline T Align(T Value, uint64_t Alignment)
		{
			return ((Value)+((Alignment)-T(1))) & ~((Alignment)-T(1));
		}

		template<typename T>
		__forceinline T* Align(T* Value, uint64_t Alignment)
		{
			return (((uintptr_t)Value) + ((Alignment)-T(1))) & ~((Alignment)-T(1));
		}
	}

	template<typename T>
	struct TinyPool
	{
		static constexpr uint64_t kMaxPoolSize = 64ull;
		T* Alloc() { unsigned long Index = 0; return _BitScanForward64(&Index, Bitmap) ? &Pool[AllocBit((uint64_t)Index)] : nullptr; }
		void Free(T* Ptr) { FreeBit(GetIndex(Ptr)); }
		inline bool CanAllocate() const { return Bitmap > 0ull; }
		inline bool IsPtrAllocated(const T* Ptr) const { return IsBitAllocated(GetIndex(Ptr)); }
		inline bool OwnsAllocation(const T* Ptr) const { return ((uint64_t)Ptr - (uint64_t)Pool) < sizeof(Pool); }
		inline uint64_t GetAvailableCount() const { return __popcnt64(Bitmap); }
		inline uint64_t GetUsedCount() const { return kMaxPoolSize - __popcnt64(Bitmap); }

	private:
		inline uint64_t GetIndex(const T* Ptr) const { return ((uint64_t)Ptr - (uint64_t)Pool) / sizeof(T); }
		inline bool IsBitAllocated(uint64_t Index) const { return Index < kMaxPoolSize && ((Bitmap& (1ull << Index)) == 0ull); }
		inline uint64_t AllocBit(uint64_t Index) { Bitmap &= ~(1ull << Index); return Index; }
		inline void FreeBit(uint64_t Index) { if (Index < kMaxPoolSize) Bitmap |= (1ull << Index); }

		T Pool[kMaxPoolSize];
		uint64_t Bitmap = ~0ull;
	};

	struct RefCounter
	{
		inline void IncRef()
		{
			_InterlockedIncrement64(&Counter);
		}
		inline bool DecRef()
		{
			return _InterlockedDecrement64(&Counter) == 0;
		}
		inline int64_t GetCount()
		{
			return _InterlockedCompareExchange64(&Counter, 0, 0);
		}
	private:
		int64_t Counter = 0;
	};

	struct SystemMemoryInfo
	{
		static SystemMemoryInfo& Get()
		{
			static SystemMemoryInfo Instance{};
			return Instance;
		}

		SystemMemoryInfo()
		{
			SYSTEM_INFO SystemInfo = {};
			GetSystemInfo(&SystemInfo);
			PageSize = (uint64_t)SystemInfo.dwPageSize;
			AllocationGranularity = (uint64_t)SystemInfo.dwAllocationGranularity;
		}

		uint64_t PageSize = 0;
		uint64_t AllocationGranularity = 0;
	};

	enum class MemoryProtection
	{
		MEMPROT_READONLY,
		MEMPROT_READWRITE
	};

	struct VirtualMemoryBlock final
	{
		static VirtualMemoryBlock AllocateVirtualMemoryBlock(uint64_t Size)
		{
			VirtualMemoryBlock Block{};
			uint64_t AlignedSize = utility::Align(Size, SystemMemoryInfo::Get().PageSize);
			Block.MappingObject = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE | SEC_RESERVE, 0, (uint32_t)AlignedSize, nullptr);
			ASSERT(Block.MappingObject != nullptr);
			Block.VirtualAddress = MapViewOfFile(Block.MappingObject, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, AlignedSize);
			ASSERT(Block.VirtualAddress != nullptr);
			Block.ReservedSize = AlignedSize;
			Block.Ref = RefCounterPool.Alloc();
			Block.Ref->IncRef();
			return Block;
		}
		static void FreeVirtualMemoryBlock(VirtualMemoryBlock& InBlock)
		{
			if (InBlock.Ref == nullptr) return;
			UnmapViewOfFile(InBlock.VirtualAddress);
			if (InBlock.Ref->DecRef())
			{
				ASSERT(CloseHandle(InBlock.MappingObject) == TRUE);
				RefCounterPool.Free(InBlock.Ref);
				InBlock.Ref = nullptr;
			}
			InBlock.ReservedSize = 0;
			InBlock.VirtualAddress = nullptr;
			InBlock.MappingObject = nullptr;
		}
		static bool RemapVirtualMemoryBlock(VirtualMemoryBlock& DestBlock, VirtualMemoryBlock& SrcBlock)
		{
			if (DestBlock.ReservedSize != SrcBlock.ReservedSize)
			{
				return false;
			}
			if (SrcBlock.SetMemoryProtection(MemoryProtection::MEMPROT_READONLY))
			{
				void* SrcVirtualAddress = SrcBlock.VirtualAddress;
				FreeVirtualMemoryBlock(SrcBlock);
				SrcBlock = DestBlock;
				SrcBlock.VirtualAddress = SrcVirtualAddress;
				bool bMapResult = MapViewOfFileEx(DestBlock.MappingObject, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, DestBlock.ReservedSize, SrcBlock.VirtualAddress) == SrcBlock.VirtualAddress;
				bool bAccessResult = SrcBlock.SetMemoryProtection(MemoryProtection::MEMPROT_READWRITE);
				return bMapResult && bAccessResult;
			}
			return false;
		}

		VirtualMemoryBlock() = default;
		VirtualMemoryBlock(VirtualMemoryBlock&& Other) noexcept
		{
			Ref = Other.Ref;
			MappingObject = Other.MappingObject;
			VirtualAddress = Other.VirtualAddress;
			ReservedSize = Other.ReservedSize;
			Other.Ref = nullptr;
			Other.MappingObject = nullptr;
			Other.VirtualAddress = nullptr;
			Other.ReservedSize = 0;
		}
		VirtualMemoryBlock(const VirtualMemoryBlock& Other)
		{
			Ref = Other.Ref;
			MappingObject = Other.MappingObject;
			VirtualAddress = Other.VirtualAddress;
			ReservedSize = Other.ReservedSize;
			Ref->IncRef();
		}
		~VirtualMemoryBlock()
		{
			ASSERT(VirtualAddress == nullptr); /* call static VirtualMemoryBlock::FreeVirtualBlock() on this block */
		}
		VirtualMemoryBlock& operator=(VirtualMemoryBlock&& Other) noexcept
		{
			Ref = Other.Ref;
			MappingObject = Other.MappingObject;
			VirtualAddress = Other.VirtualAddress;
			ReservedSize = Other.ReservedSize;
			Other.Ref = nullptr;
			Other.MappingObject = nullptr;
			Other.VirtualAddress = nullptr;
			Other.ReservedSize = 0;
			return *this;
		}
		VirtualMemoryBlock& operator=(const VirtualMemoryBlock& Other)
		{
			Ref = Other.Ref;
			MappingObject = Other.MappingObject;
			VirtualAddress = Other.VirtualAddress;
			ReservedSize = Other.ReservedSize;
			Ref->IncRef();
			return *this;
		}
		bool CommitBlock(bool bForcePageFault = false)
		{
			bool bResult = VirtualAlloc(VirtualAddress, ReservedSize, MEM_COMMIT, PAGE_READWRITE) == VirtualAddress;
			volatile uint64_t ValueToForceMapping = 0;
			/* Force page fault for testing purpose */
			if (bResult && bForcePageFault && VirtualAddress != nullptr)
			{
				for (uint64_t Index = 0; Index < ReservedSize; ++Index)
				{
					ValueToForceMapping += *((uint8_t*)VirtualAddress + Index);
				}
				return bResult || ((uint64_t)bResult * ValueToForceMapping > 0);
			}
			return bResult;
		}
		bool SetMemoryProtection(MemoryProtection Protection)
		{
			DWORD OldProtect = 0;
			bool bResult = VirtualProtect(VirtualAddress, ReservedSize, Protection == MemoryProtection::MEMPROT_READONLY ? PAGE_READONLY : PAGE_READWRITE, &OldProtect);
			return bResult;
		}
		void* GetVirtualAddress() const
		{
			return VirtualAddress;
		}
		uint64_t GetReservedSize() const
		{
			return ReservedSize;
		}
		bool IsBlockCommitted() const
		{
			MEMORY_BASIC_INFORMATION MemBasicInfo = {};
			if (VirtualQuery(VirtualAddress, &MemBasicInfo, sizeof(MemBasicInfo)) > 0)
			{
				return (MemBasicInfo.State & MEM_COMMIT) > 0;
			}
			return false;
		}
		bool IsBlockAccessReadWrite() const
		{
			MEMORY_BASIC_INFORMATION MemBasicInfo = {};
			if (VirtualQuery(VirtualAddress, &MemBasicInfo, sizeof(MemBasicInfo)) > 0)
			{
				return (MemBasicInfo.AllocationProtect & PAGE_READWRITE) > 0;
			}
			return false;
		}

	private:
		RefCounter* Ref = nullptr;
		HANDLE MappingObject = nullptr;
		void* VirtualAddress = nullptr;
		uint64_t ReservedSize = 0;

	public:
		static TinyPool<RefCounter> RefCounterPool;
	};
}

mem::TinyPool<mem::RefCounter> mem::VirtualMemoryBlock::RefCounterPool;

#if ALLOW_LOG
#include <stdarg.h>
void DebugLog(bool bNewLine, const char* Fmt, ...)
{
	char Buffer[1024] = {};
	va_list VaList;
	va_start(VaList, Fmt);
	vsprintf_s(Buffer, 1024, Fmt, VaList);
	va_end(VaList);
	OutputDebugStringA(Buffer);
	if (bNewLine) OutputDebugStringA("\n");
#if ALLOW_WAIT
	printf(Buffer);
#endif
}
#define DBG_LOG(NewLine, Fmt, ...) DebugLog(NewLine, Fmt, __VA_ARGS__)
#else
#define DBG_LOG(NewLine, Fmt, ...)
#endif

#if ALLOW_WAIT
#define STEP(msg) DBG_LOG(true, "Press Enter To => %s", msg); { char v = getchar(); }
#define LOG(msg, ...) DBG_LOG(false, msg "\n", __VA_ARGS__);
#else
#define STEP(msg) DBG_LOG(true, "Step => %s\n", msg);
#define LOG(msg, ...) DBG_LOG(false, msg "\n", __VA_ARGS__);
#endif

int main()
{
	const uint64_t BlockSize = mem::SystemMemoryInfo::Get().PageSize;
	const uint64_t BlockOffset = 0x48;

	uint32_t ProcessId = GetCurrentProcessId();
	LOG("PID => %x", ProcessId);
	STEP("Reserve 2 Virtual Blocks");

	mem::VirtualMemoryBlock Block1 = mem::VirtualMemoryBlock::AllocateVirtualMemoryBlock(BlockSize);
	mem::VirtualMemoryBlock Block2 = mem::VirtualMemoryBlock::AllocateVirtualMemoryBlock(BlockSize);

	LOG("	Block1 Virtual Address = 0x%016" PRIx64 "", (uintptr_t)Block1.GetVirtualAddress());
	LOG("	Block2 Virtual Address = 0x%016" PRIx64 "", (uintptr_t)Block2.GetVirtualAddress());

	void* Block1WorkingAddr = Block1.GetVirtualAddress();
	void* Block2WorkingAddr = mem::utility::OffsetPtr(Block2.GetVirtualAddress(), BlockOffset);

	STEP("CommitBlock Block1");
	ASSERT(Block1.CommitBlock(true));
	STEP("CommitBlock Block2");
	ASSERT(Block2.CommitBlock(true));

	STEP("Write data to blocks");
	memset(Block1WorkingAddr, 0xAA, BlockOffset);
	memset(Block2WorkingAddr, 0xFF, BlockOffset);

	STEP("Copy contents of Block2 to Block1 before remapping");
	memcpy(mem::utility::OffsetPtr(Block1WorkingAddr, BlockOffset), Block2WorkingAddr, BlockOffset);

	STEP("Remap Block2's virtual address to Block1 physical address");
	ASSERT(mem::VirtualMemoryBlock::RemapVirtualMemoryBlock(Block1, Block2));
	{ volatile uint8_t X = *(uint8_t*)Block2WorkingAddr; } /* force page fault */

	STEP("Release Block1");
	mem::VirtualMemoryBlock::FreeVirtualMemoryBlock(Block1);

	STEP("Release Block2");
	mem::VirtualMemoryBlock::FreeVirtualMemoryBlock(Block2);

	STEP("Finish...");
	return 0;
}
