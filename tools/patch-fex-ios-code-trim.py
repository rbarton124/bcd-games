#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""A 32-bit process gives its FEX code buffer back for a small one when BCD's ntdll asks (madeira-bcd code-trim).

Every pseudo-process's FEX keeps one code buffer generation per process, carved from the JIT pool's tail, and a background program
keeps its buffers for the whole session even when it runs nothing new: Ubisoft Connect's processes held 320-352 MB of the pool's
~480 MB of code buffers while Far Cry 3 played (2026-11-03/04), none of them switched generation during play, and the game ran on
16 MB buffers it replaced every 1-2 s. FEX can already move every thread of a process to a new generation (the ml460/ml1106 sweep,
the ml1430 syscall parking); this patch adds the two things missing:

* IosTrimCodeBuffer (FEXCore CPUBackend.cpp, beside IosMaybeSweepCodeBuffers): start a small generation and move EVERY thread to it
  at once, so all older generations lose their last reference and go back to the pool. All or nothing, under the sweep's gate:
  every other registered thread must be parked (IosInSim == 0) and none may have a signal frame, or nothing changes. The new size is
  probed first, so FEX's last-resort fault on a failed code-buffer allocation cannot hit a process that was only asked to shrink.
* The request (WOW64 Module.cpp): ntdll owns a control block per process; the Wine-private NtQueryInformationProcess class 1011
  (ProcessWineIosCodeTrim, next to BCD's 1010 ProcessWineIosWowGuestBase) returns its address, asked once per process on the first
  outermost syscall. At the end of every outermost syscall (IosWowSyscallC) a pending request is tried: the thread is outside
  emitted code there and, once moved, resumes at the dispatcher exactly like a parked thread the sweeper moved. A declined try is
  repeated a second later by whichever thread comes by. An ntdll without the class answers an error: the process never trims,
  and costs one query.

No export changes (the WOW64 build ships its module only when the exports equal the committed xtajit.dll's). Needs the syscall
parking (MADEIRA_WOW_SYSCALL_SWEEP, on by default) and a sweep registry that never overflowed. Not applied to the ARM64EC module.
Logs: "[gen-trim] code-buffer trim offered|not offered", "[gen-trim] code buffer 0x... -> 0x...: N threads moved ...", and
"[gen-trim] declined: ...".

Applied to the FEX tree before the WOW64 module is built (tools/build-xtajit-wow64.sh, build/fex-wow64/build.sh), after the other
WOW64 patches; both restore the files afterwards. A changed anchor refuses the patch and the build goes on without it (a warning).

Usage: patch-fex-ios-code-trim.py <FEX tree>
Idempotent: a second run says "already in" and changes nothing.
"""
from pathlib import Path
import sys

MARKER = "madeira-bcd code-trim"
HEADER = "FEXCore/Source/Interface/Core/CPUBackend.h"
BACKEND = "FEXCore/Source/Interface/Core/CPUBackend.cpp"
MODULE = "Source/Windows/WOW64/Module.cpp"

# ---------------------------------------------------------------- CPUBackend.h: the manager starts a buffer for a trim
H_ANCHOR = ("    std::mutex LatestMutex;\n"
            "#endif\n"
            "\n"
            "  private:\n"
            "    fextl::shared_ptr<CodeBuffer> Latest;\n")
H_NEW = ("    std::mutex LatestMutex;\n"
         "\n"
         "    // " + MARKER + " (tools/patch-fex-ios-code-trim.py): the new, smaller latest buffer of a trim (IosTrimCodeBuffer).\n"
         "    fextl::shared_ptr<CodeBuffer> IosStartCodeBuffer(size_t Size) {\n"
         "      return AllocateNew(Size);\n"
         "    }\n"
         "#endif\n"
         "\n"
         "  private:\n"
         "    fextl::shared_ptr<CodeBuffer> Latest;\n")

# ---------------------------------------------------------------- CPUBackend.cpp: the registry knows when it overflowed; the trim
B_BUSY = "    std::atomic<uint32_t> IosSweepBusy {0};\n"
B_BUSY_NEW = (B_BUSY +
              "    // " + MARKER + ": a thread went unregistered, so a trim could not see every thread of the process\n"
              "    std::atomic<bool> IosSweepRegistryFull {false};\n")
B_FULL = '    LogMan::Msg::EFmt("[gen-sweep] registry FULL — thread unswept rev=ml460");\n'
B_FULL_NEW = ("    IosSweepRegistryFull.store(true, std::memory_order_relaxed); // " + MARKER + "\n" + B_FULL)

B_END = ("#endif\n"
         "\n"
         "  bool CPUBackend::IsAddressInCodeBuffer(uintptr_t Address) const {\n")
B_TRIM = r'''
#if !defined(ARCHITECTURE_arm64ec)
  /* madeira-bcd code-trim (tools/patch-fex-ios-code-trim.py): give this process's code buffers back for one small new generation,
   * on BCD's request (an idle background program while the program being played is short of pool; build/ntdll-unix/virtual_ios.c).
   * The sweep above moves parked threads to a generation the process created itself; this creates a small one and moves EVERY
   * thread to it, so every older generation loses its last reference and returns to the pool. Called at the end of an outermost
   * syscall (WOW64 Module.cpp IosWowSyscallC), where the caller is outside emitted code and resumes at the dispatcher once moved.
   *
   * All or nothing, with the sweep's safety model: the sweep claim (IosSweepBusy, which also holds thread teardown), the shared
   * CodeInvalidationMutex and CodeBufferWriteMutex (try-locks: a code change or a compile in flight declines), then the gate; every
   * other registered thread must be parked (IosInSim == 0, so it cannot re-enter emitted code until the gate clears) and no thread
   * may have a signal frame. A first look without the gate declines at once when a thread is plainly not parked, and only then is
   * the new size probed (FEX's last-resort fault on a failed code buffer must not hit a process that was only asked to shrink;
   * ntdll does not hold the probe for anyone, as it was handed out after the request).
   *
   * Returns 1 done (the caller moved too), 2 done but the caller kept its buffer, 0 declined (a thread not parked or with a signal
   * frame), -1 not possible in this process (the registry overflowed), -2 busy (another sweep, a code change or a compile),
   * -3 no room for the new buffer. Out: threads, moved, not parked, signal frames, old size, new size. */
  extern "C" int IosTrimCodeBuffer(FEXCore::Core::InternalThreadState* CallerThread, size_t Size, uint64_t* Out) {
    for (int i = 0; i < 6; i++) {
      Out[i] = 0;
    }
    if (IosSweepRegistryFull.load(std::memory_order_relaxed)) {
      return -1;
    }
    {
      std::scoped_lock lk {IosSweepRegistryLock()};
      for (size_t i = 0; i < IosSweepSlotHighWater; i++) {
        if (IosSweepSlots[i].Thread && IosSweepSlots[i].Thread != CallerThread) {
          Out[0]++;
          Out[2] += *IosSweepSlots[i].InSim != 0;
        }
      }
    }
    if (Out[2]) {
      Out[0]++;
      return 0; // a thread is plainly not parked: decline before the probe (the gate's test below is the one that counts)
    }
    Out[0] = 0;
    if (void* Probe = FEXCore::Allocator::VirtualAlloc(Size, true)) {
      FEXCore::Allocator::VirtualFree(Probe, Size);
    } else {
      return -3;
    }
    if (IosSweepBusy.exchange(1, std::memory_order_acq_rel) != 0) {
      return -2;
    }
    auto& Invalidation = CallerThread->CTX->GetCodeInvalidationMutex();
    auto& Manager = CallerThread->CPUBackend->GetCodeBufferManager();
    if (!Invalidation.try_lock_shared()) {
      IosSweepBusy.store(0, std::memory_order_release);
      return -2;
    }
    if (!Manager.CodeBufferWriteMutex.try_lock()) {
      Invalidation.unlock_shared();
      IosSweepBusy.store(0, std::memory_order_release);
      return -2;
    }

    IosSweepSlot Snap[IosSweepSlotMax];
    size_t SnapCount = 0;
    {
      std::scoped_lock lk {IosSweepRegistryLock()};
      for (size_t i = 0; i < IosSweepSlotHighWater; i++) {
        if (IosSweepSlots[i].Thread && IosSweepSlots[i].Thread != CallerThread) {
          Snap[SnapCount++] = IosSweepSlots[i];
        }
      }
    }

    __atomic_store_n(&IosCodeBufferSweepGate, 1, __ATOMIC_SEQ_CST);
    std::atomic_thread_fence(std::memory_order_seq_cst);

    uint64_t NotParked = 0, SignalFrames = CallerThread->CurrentFrame->SignalHandlerRefCounter != 0;
    for (size_t i = 0; i < SnapCount; i++) {
      if (*Snap[i].InSim != 0) {
        NotParked++;
      } else if (Snap[i].Thread->CurrentFrame->SignalHandlerRefCounter != 0) {
        SignalFrames++;
      }
    }
    int Result = 0;
    if (!NotParked && !SignalFrames) {
      Out[4] = Manager.GetLatest()->AllocatedSize;
      auto Latest = Manager.IosStartCodeBuffer(Size);
      for (size_t i = 0; i < SnapCount; i++) {
        if (Snap[i].Thread->CPUBackend->IosRemoteMigrateStale(Latest) == 1) {
          Out[1]++;
          // Written while the gate is still set, as the sweep does: the owner reads it after its own gate spin.
          if (Snap[i].Migrated) {
            *Snap[i].Migrated = 1;
          }
        }
      }
      Result = CallerThread->CPUBackend->IosRemoteMigrateStale(Latest) == 1 ? 1 : 2;
      Out[5] = Latest->AllocatedSize;
    }

    std::atomic_thread_fence(std::memory_order_seq_cst);
    __atomic_store_n(&IosCodeBufferSweepGate, 0, __ATOMIC_SEQ_CST);
    Manager.CodeBufferWriteMutex.unlock();
    Invalidation.unlock_shared();
    IosSweepBusy.store(0, std::memory_order_release);
    Out[0] = SnapCount + 1;
    Out[2] = NotParked;
    Out[3] = SignalFrames;
    return Result;
  }
#endif
'''
B_END_NEW = B_TRIM + B_END

# ---------------------------------------------------------------- WOW64 Module.cpp: the request and where it is tried
M_DECL = 'extern "C" uint64_t IosCodeBufferSweepGate;\n'
M_DECL_NEW = (M_DECL +
              'extern "C" int IosTrimCodeBuffer(FEXCore::Core::InternalThreadState* CallerThread, size_t Size, uint64_t* Out); // '
              + MARKER + '\n')

M_BEFORE = "// Returns the HOST address of the 32-bit TEB paired with the given 64-bit TEB.\n"
M_TRIM = r'''/* madeira-bcd code-trim (tools/patch-fex-ios-code-trim.py): BCD's ntdll may ask this process to give its code buffers back for a
 * small new one (an idle background program while the program being played is short of pool; build/ntdll-unix/virtual_ios.c,
 * struct ios_code_trim). The request lives in a control block ntdll owns; the Wine-private NtQueryInformationProcess class 1011
 * returns its address, asked once on the first outermost syscall. An ntdll without the class answers an error and this process
 * never trims. Poll runs at the end of every outermost syscall (IosWowSyscallC) and costs a few loads when nothing is asked;
 * IosTrimCodeBuffer (CPUBackend.cpp) does the trim, all or nothing; a declined or busy try is repeated a second later by
 * whichever thread comes by, at most GiveUp times for one request (ntdll may ask again later). */
namespace IosCodeTrim {
static constexpr ULONG ProcessWineIosCodeTrim = 1011;
static constexpr uint32_t ControlMagic = 0x4d495254; // "TRIM"

struct Control { // the layout of build/ntdll-unix/virtual_ios.c struct ios_code_trim
  uint32_t Magic;
  uint32_t SizeMB;            // the size of the new buffer, in MB
  volatile uint32_t Request;  // ntdll: one more for each request
  volatile uint32_t Done;     // this process: the request it last finished
  volatile int32_t Result;    // IosTrimCodeBuffer's answer to it (1 or 2 done, -1 not possible here, -3 no room)
  volatile uint32_t Declined; // tries declined or busy since then
};

static std::atomic<int8_t> State {-1}; // -1 not asked yet, 0 not offered, 1 offered
static Control* Ctl {};
static std::atomic<int64_t> NextTry {}; // NtQuerySystemTime units
static constexpr uint32_t GiveUp = 30;  // declined or busy tries for one request

static Control* Get() {
  int8_t S = State.load(std::memory_order_acquire);
  if (S < 0) {
    ULONG_PTR Address = 0;
    const NTSTATUS Err = NtQueryInformationProcess(NtCurrentProcess(), static_cast<PROCESSINFOCLASS>(ProcessWineIosCodeTrim), &Address,
                                                   sizeof(Address), nullptr);
    auto* C = reinterpret_cast<Control*>(Address);
    const bool Offered = !Err && C && C->Magic == ControlMagic;
    int8_t Expected = -1;
    if (State.compare_exchange_strong(Expected, -2, std::memory_order_acq_rel)) {
      Ctl = Offered ? C : nullptr;
      State.store(Offered ? 1 : 0, std::memory_order_release);
      LogMan::Msg::EFmt("[gen-trim] code-buffer trim {} (class {} status {:#x}; madeira-bcd code-trim)", Offered ? "offered" : "not offered",
                        ProcessWineIosCodeTrim, static_cast<uint32_t>(Err));
    }
    S = State.load(std::memory_order_acquire);
  }
  return S > 0 ? Ctl : nullptr;
}

static void Poll(FEXCore::Core::InternalThreadState* Thread, FrontendThreadData* TD) {
  Control* C = Get();
  if (!C) {
    return;
  }
  const uint32_t Request = __atomic_load_n(&C->Request, __ATOMIC_ACQUIRE);
  if (Request == __atomic_load_n(&C->Done, __ATOMIC_RELAXED)) {
    return;
  }
  LARGE_INTEGER Now;
  NtQuerySystemTime(&Now);
  int64_t Next = NextTry.load(std::memory_order_relaxed);
  if (Now.QuadPart < Next || !NextTry.compare_exchange_strong(Next, Now.QuadPart + 10000000, std::memory_order_relaxed)) {
    return; // one try a second, by one thread
  }
  uint64_t Out[6];
  const int Result = IosTrimCodeBuffer(Thread, static_cast<size_t>(C->SizeMB) << 20, Out);
  static std::atomic<int> LogCount {0};
  const bool Log = LogCount.fetch_add(1, std::memory_order_relaxed) < 32;
  if ((Result == 0 || Result == -2) && __atomic_add_fetch(&C->Declined, 1, __ATOMIC_RELAXED) < GiveUp) {
    if (Log) {
      LogMan::Msg::EFmt("[gen-trim] declined (request {}): {} of {} threads not parked, {} with a signal frame{}; tried again in 1 s", Request,
                        Out[2], Out[0], Out[3], Result == -2 ? ", or a sweep, code change or compile in flight" : "");
    }
    return;
  }
  if (Result == 1) {
    TD->IosMigrated = 1; // this thread's code buffer moved too: resume at the dispatcher (below)
  }
  __atomic_store_n(&C->Result, Result, __ATOMIC_RELAXED);
  __atomic_store_n(&C->Declined, 0, __ATOMIC_RELAXED);
  __atomic_store_n(&C->Done, Request, __ATOMIC_RELEASE);
  if (Log) {
    if (Result > 0) {
      LogMan::Msg::EFmt("[gen-trim] code buffer {:#x} -> {:#x}: {} of {} other threads moved to it, this one {} (request {})", Out[4], Out[5],
                        Out[1], Out[0] - 1, Result == 1 ? "too" : "not", Request);
    } else {
      LogMan::Msg::EFmt("[gen-trim] not trimmed (request {}): {}", Request,
                        Result == -1   ? "a thread went unregistered, so not every thread can be seen"
                        : Result == -3 ? "no room for the new buffer"
                                       : "declined 30 times (a thread never parked); ntdll may ask again");
    }
  }
}
} // namespace IosCodeTrim

'''
M_BEFORE_NEW = M_TRIM + M_BEFORE

M_HOOK = ("  TD->IosSyscallArmed = PrevArmed;\n"
          "  TD->IosSyscallDepth = Depth;\n"
          "  if (Arm && TD->IosMigrated) {\n")
M_HOOK_NEW = ("  TD->IosSyscallArmed = PrevArmed;\n"
              "  TD->IosSyscallDepth = Depth;\n"
              "  if (Arm) {\n"
              "    IosCodeTrim::Poll(TLS.ThreadState(), TD); // " + MARKER + ": a pending request; sets IosMigrated when this thread moved\n"
              "  }\n"
              "  if (Arm && TD->IosMigrated) {\n")

EDITS = {
    HEADER: [(H_ANCHOR, H_NEW, 1)],
    BACKEND: [(B_BUSY, B_BUSY_NEW, 1), (B_FULL, B_FULL_NEW, 2), (B_END, B_END_NEW, 1)],
    MODULE: [(M_DECL, M_DECL_NEW, 1), (M_BEFORE, M_BEFORE_NEW, 1), (M_HOOK, M_HOOK_NEW, 1)],
}


def patch(name, text):
    """The patched text of one file; ValueError for a changed or partly patched file."""
    edits = EDITS[name]
    if MARKER in text:
        if all(text.count(new) == count for _, new, count in edits):
            return text
        raise ValueError(name + ": partly or differently patched")
    for old, _, count in edits:
        if text.count(old) != count:
            raise ValueError(name + ": anchor changed: " + old.strip().splitlines()[0][:80])
    for old, new, _ in edits:
        text = text.replace(old, new)
    return text


def main(argv):
    if len(argv) != 2:
        sys.exit(__doc__.strip().splitlines()[-2])
    tree = Path(argv[1])
    sources = {name: (tree / name).read_text() for name in EDITS}
    try:
        results = {name: patch(name, text) for name, text in sources.items()}   # all files checked before any is written
    except ValueError as error:
        sys.exit("patch-fex-ios-code-trim: " + str(error))
    if results == sources:
        print("patch-fex-ios-code-trim: already in")
        return
    for name, text in results.items():
        if text != sources[name]:
            (tree / name).write_text(text)
    print("FEX WOW64: a process gives its code buffer back for a small one when BCD asks ([gen-trim])")


if __name__ == "__main__":
    main(sys.argv)
