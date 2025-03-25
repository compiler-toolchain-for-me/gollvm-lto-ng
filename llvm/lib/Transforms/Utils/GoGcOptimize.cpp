//===--- GoGcOptimize.cpp -------------------------------------------------===//
//
// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
//
// LLVM backend pass to make sure inlined getg's are
// safe. Specifically, make sure the TLS address is not
// cached across a thread switch.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Utils/GoGcOptimize.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"
#include "llvm/SandboxIR/Value.h"
#include "llvm/Support/Debug.h"

#include <algorithm>
#include <array>
#include <numeric>
#include <set>

#define DEBUG_TYPE "gogcoptimize"

using namespace llvm;

namespace {
STATISTIC(NumOfAllocs, "Number of GC allocations found");
STATISTIC(NumOfCallsToNewObject, "Number of calls to runtime.newobject");
STATISTIC(NumOfCallsToMallocGC, "Number of calls to runtime.mallocgc");
STATISTIC(NumRemovedGCWB, "Number of removed calls to runtime.gcWriteBarrier");
STATISTIC(NumConvertedMemMoves,
          "Number of calls to runtime.typedmemmove converted to memcpy");
STATISTIC(NumOptimizableGCAllocs,
          "Number of GC allocations possible to optimize");

#define DEFINE_GC_LEAK(a, b)                                                   \
  llvm::Statistic NumGcObj##a = {DEBUG_TYPE ".VK_GcObject", "NumGcObj" #a, b};
#include "GoGcLeakKind.def"

#define DEFINE_GC_LEAK(a, b)                                                   \
  llvm::Statistic NumFArg##a = {DEBUG_TYPE ".VK_FuncArg", "NumFArg" #a, b};
#include "GoGcLeakKind.def"

Statistic *GcObjectStats[] = {
#define DEFINE_GC_LEAK(a, b) &NumGcObj##a,
#include "GoGcLeakKind.def"
    nullptr};

Statistic *GcFArgStats[] = {
#define DEFINE_GC_LEAK(a, b) &NumFArg##a,
#include "GoGcLeakKind.def"
    nullptr};

////////////////////////////////////////////////////////////////////
class ValueTracker {
public:
  enum ValueKind { VK_GCPointer, VK_FuncArg, _VK_Last };
  struct SizeAlign {
    uint64_t Size : 56;
    uint64_t Align : 8;
  };
  typedef SmallVector<int64_t, 4> PtrOffsetInfo;

  ValueTracker(Module &Mod, FunctionAnalysisManager &FAM) : M(Mod), FAM(FAM) {}

  bool trackGCPointer(Value *V);
  void updateStats();
  static SizeAlign getGoTypeSizeAlign(Value *TypeDesc);
  static SizeAlign getGoTypeSizeAlignFromCall(CallBase *CB);
  static Value *getGoCallOperand(CallBase *CB, int I);
  static bool allocationZeroesMemory(CallBase *CB);

  std::vector<CallBase *> OptimizableGCAllocs;

private:
  struct ValueEscapeInfo {
    enum LeakKind : uint32_t {
#define DEFINE_GC_LEAK(a, b) a,
#include "GoGcLeakKind.def"
      _LastKind
    };
    LeakKind LK;
    ValueKind VK;
    Value *Val;
    PtrOffsetInfo POI;
  };

  LLVM_ATTRIBUTE_USED static void
  dumpValueMap(const DenseMap<Value *, PtrOffsetInfo> &ValueMap);
  bool trackEscape(ValueKind VK, Value *V, const PtrOffsetInfo &POI);
  static bool getValueAsConstI64(Value *V, int64_t *P);
  static bool isPassthroughInstruction(Value *V);
  static bool shouldIgnore(Value *V);
  StringRef leakKindName(int K);

  void onEscape(ValueKind VK, ValueEscapeInfo::LeakKind LK, Value *V, Value *S,
                const PtrOffsetInfo *POI) {}
  void onUse(Use *U) {}

  bool notEscaped(ValueKind VK, Value *V) {
    return escaped(VK, ValueEscapeInfo::NotLeaked, V, nullptr);
  }
  bool hasArgEscapeInfo(Value* V, const PtrOffsetInfo& POI, bool& Escaped);

  // Returns true if we should stop analysis, in such
  // case Escaped contains return status
  bool startEscapingAnalysis(ValueKind VK, Value* V, const PtrOffsetInfo& POI, bool& Escaped);
  bool escaped(ValueKind VK, ValueEscapeInfo::LeakKind LK, Value *V, Value *S,
               const PtrOffsetInfo *POI = nullptr);

  static unsigned getFnArgNo(Function *F, Value *Arg);
  ValueEscapeInfo::LeakKind identifyStoreTarget(Value *Op, PtrOffsetInfo &POI,
                                                Value **V);
  void addArgEscapeInfoIfNeeded(SmallVectorImpl<ValueEscapeInfo> &VEIList,
                                const ValueEscapeInfo &VI);
  static bool isKnownAllocationFunction(Function *F) {
    return F ? isKnownAllocationFunction(F->getName()) : false;
  }
  bool hasGoStructRetArg(CallBase *CB, unsigned ArgNo) {
    unsigned AttrIdx = ArgNo + AttributeList::FirstArgIndex;
    Attribute A = CB->getAttributeAtIndex(AttrIdx, "go_sret");
    return A.isValid();
  }
  bool subtractOffset(unsigned &Dest, unsigned N);

  static bool isKnownAllocationFunction(StringRef Name);
  bool getGEPOffset(Value *GEP, int64_t &Offset);
  unsigned getOffsetInAggregate(Type *TyAgg, ArrayRef<unsigned> Indices);

  bool isLoopInvariant(Value *V);
  bool mayLoadPointer(const PtrOffsetInfo &POI, unsigned Off, unsigned Size);
  bool mayAliasPointer(Value *Op, int64_t Size, const PtrOffsetInfo &POI);

  Module &M;
  FunctionAnalysisManager &FAM;
  DenseMap<Value *, ValueEscapeInfo> ValueEscapeMap;  
  DenseMap<std::pair<Value*, PtrOffsetInfo>, SmallVector<ValueEscapeInfo, 4>> ArgEscapeMap;
  DenseMap<Value*, PtrOffsetInfo> ArgMap;
};

LLVM_ATTRIBUTE_USED raw_ostream &
operator<<(raw_ostream &OS, const ValueTracker::PtrOffsetInfo &POI) {
  OS << "{";
  for (unsigned I = 0; I < POI.size(); ++I) {
    OS << POI[I];
    if (I < POI.size() - 1)
      OS << ",";
  }
  OS << "}";
  return OS;
}

bool ValueTracker::subtractOffset(unsigned &Dest, unsigned N) {
  if (N > Dest)
    return false;
  Dest -= N;
  return true;
}

unsigned ValueTracker::getFnArgNo(Function *F, Value *Arg) {
  for (unsigned I = 0; I < F->arg_size(); ++I)
    if (F->getArg(I) == Arg)
      return I;
  return -1U;
}

bool ValueTracker::isKnownAllocationFunction(StringRef Name) {
  return Name == "runtime.mallocgc" || Name == "runtime.newobject";
}

bool ValueTracker::getGEPOffset(Value *V, int64_t &Offset) {
  auto *GEP = cast<GEPOperator>(V);
  APInt APOffset(M.getDataLayout().getIndexTypeSizeInBits(GEP->getType()), 0);
  if (!GEP->accumulateConstantOffset(M.getDataLayout(), APOffset))
    return false;
  Offset = APOffset.getSExtValue();
  return Offset >= 0 ? true : false;
}

unsigned ValueTracker::getOffsetInAggregate(Type *TyAgg,
                                            ArrayRef<unsigned> Indices) {
  SmallVector<Value *, 4> VInds;
  Type *IdxTy = Type::getInt32Ty(TyAgg->getContext());
  VInds.push_back(ConstantInt::get(IdxTy, 0));
  for (auto I : Indices)
    VInds.push_back(ConstantInt::get(IdxTy, I));
  return M.getDataLayout().getIndexedOffsetInType(TyAgg, VInds);
}

bool ValueTracker::trackGCPointer(Value *V) {
  assert(ArgMap.empty());
  CallBase *CB = cast<CallBase>(V);
  NumOfAllocs++;
  StringRef Name = CB->getCalledFunction()->getName();
  if (Name == "runtime.newobject")
    NumOfCallsToNewObject++;
  else if (Name == "runtime.mallocgc")
    NumOfCallsToMallocGC++;
  else
    llvm_unreachable("unsupported GC alloc type");
  auto SizeAlign = getGoTypeSizeAlignFromCall(CB);
  if (SizeAlign.Size > 1024)
    return escaped(VK_GCPointer, ValueEscapeInfo::SizeToLarge, V, V, nullptr);
  else if (SizeAlign.Size == 0 && SizeAlign.Align == 0)
    return escaped(VK_GCPointer, ValueEscapeInfo::SizeUnknown, V, V, nullptr);
  bool Escapes = trackEscape(VK_GCPointer, V, {});
  if (!Escapes)
    OptimizableGCAllocs.push_back(CB);
  return Escapes;
}

void ValueTracker::updateStats() {
  NumOptimizableGCAllocs = OptimizableGCAllocs.size();
  for (auto &P : ValueEscapeMap)
    (*GcObjectStats[P.second.LK])++;
  for (auto &P : ArgEscapeMap)
    for (auto &VEI : P.second)
      (*GcFArgStats[VEI.LK])++;
}

ValueTracker::SizeAlign ValueTracker::getGoTypeSizeAlign(Value *TypeDesc) {
  SizeAlign Ret = {};
  auto *GV = dyn_cast_or_null<GlobalVariable>(TypeDesc);
  if (GV == nullptr || !GV->hasInitializer())
    return Ret;
  auto *CS = cast<ConstantStruct>(GV->getInitializer());
  if (CS->getOperand(0)->getType()->isStructTy())
    CS = cast<ConstantStruct>(CS->getOperand(0));

  Ret.Size = cast<ConstantInt>(CS->getOperand(0))->getValue().getZExtValue();
  Ret.Align = cast<ConstantInt>(CS->getOperand(4))->getValue().getZExtValue();
  return Ret;
}

ValueTracker::SizeAlign ValueTracker::getGoTypeSizeAlignFromCall(CallBase *CB) {
  StringRef Name = CB->getCalledFunction()->getName();
  Value *TypeDesc = nullptr;
  if (Name == "runtime.mallocgc")
    TypeDesc = getGoCallOperand(CB, 1);
  else if (Name == "runtime.newobject" || Name == "runtime.typedmemmove")
    TypeDesc = getGoCallOperand(CB, 0);
  else
    llvm_unreachable("unknown allocation function");
  return getGoTypeSizeAlign(TypeDesc);
}

bool ValueTracker::allocationZeroesMemory(CallBase *CB) {
  StringRef Name = CB->getCalledFunction()->getName();
  bool Zeroext = false;
  if (Name == "runtime.mallocgc")
    Zeroext = cast<ConstantInt>(getGoCallOperand(CB, 2))->isOne();
  else if (Name == "runtime.newobject")
    Zeroext = true;
  else
    llvm_unreachable("unknown allocation function");
  return Zeroext;
}

bool ValueTracker::trackEscape(ValueKind VK, Value *VEscTest,
                               const PtrOffsetInfo &POI) {
  SmallVector<Use *, 16> Worklist;
  DenseSet<Use *> Seen;
  DenseMap<Value *, PtrOffsetInfo> ValueMap;
  auto AddUses = [&](Value *V, const PtrOffsetInfo &POI) {
    if (isa<Constant>(V))
      return true;
    auto VIt = ValueMap.find(V);
    if (VIt != ValueMap.end() && VIt->second != POI)
      return !escaped(VK, ValueEscapeInfo::MultipleOffsets, VEscTest, V, &POI);
    for (auto &U : V->uses()) {
      auto P = Seen.insert(&U);
      if (P.second) {
        ValueMap[V] = POI;
        Worklist.push_back(&U);
      }
    }
    return true;
  };

  std::function<bool(Value *, const PtrOffsetInfo &)> HandleMemCopy =
      [&](Value *STV, const PtrOffsetInfo &ValuePOI) {
        if (!isLoopInvariant(STV))
          return !escaped(VK, ValueEscapeInfo::NotLoopInvariant, VEscTest, STV,
                          &ValuePOI);
        PtrOffsetInfo POI = ValuePOI;
        Value *V = nullptr;
        ValueEscapeInfo::LeakKind LK;
        if ((LK = identifyStoreTarget(STV, POI, &V)) ==
            ValueEscapeInfo::NotLeaked) {
          if (auto *PHI = dyn_cast<PHINode>(V)) {
            for (auto &IV : PHI->incoming_values())
              if (!HandleMemCopy(IV.get(), POI))
                return false;
            return true;
          } else if (auto *SelI = dyn_cast<SelectInst>(V)) {
            return HandleMemCopy(SelI->getOperand(1), POI) &&
                   HandleMemCopy(SelI->getOperand(2), POI);
          }
          return AddUses(V, POI);
        } else {
          return !escaped(VK, LK, VEscTest, V, &POI);
        }
      };

  LLVM_DEBUG(dbgs() << "\n=== VK: " << VK << " (" << VEscTest << "): ");
  LLVM_DEBUG(VEscTest->dump());

  bool DidEscape;
  if (startEscapingAnalysis(VK, VEscTest, POI, DidEscape))
    return DidEscape;
  if (!AddUses(VEscTest, POI))
    return true;
  unsigned PtrSize = M.getDataLayout().getPointerSize();

  while (!Worklist.empty()) {
    Use *U = Worklist.back();
    assert(ValueMap.contains(U->get()));
    PtrOffsetInfo POI = ValueMap[U->get()];
    Worklist.pop_back();
    User *Ref = U->getUser();
    LLVM_DEBUG(dbgs() << "    Ref (" << Ref << "): POI: " << POI << ":");
    LLVM_DEBUG(Ref->dump());
    onUse(U);
    if (!isLoopInvariant(Ref) && (isa<CallBase>(Ref) || isa<StoreInst>(Ref)))
      return escaped(VK, ValueEscapeInfo::NotLoopInvariant, VEscTest, Ref,
                     &POI);
    if (auto *II = dyn_cast<IntrinsicInst>(Ref)) {
      switch (II->getIntrinsicID()) {
      case Intrinsic::memcpy:
      case Intrinsic::memmove:
        if (POI.empty())
          // we're reading or writing contents of our object
          // not copying pointer itself.
          continue;
        int64_t MemCopySize;
        // If amount to be copied is too small then ignore it
        if (!getValueAsConstI64(II->getOperand(2), &MemCopySize))
          MemCopySize = INT64_MAX;
        if (U->get() == II->getOperand(0)) {
          auto *SrcOp = II->getOperand(1);
          // We can't be sure about the execution order of IR instructions
          // in our program, so if we're overwriting a block of memory
          // containing pointer to our pointer we may create an alias:
          //
          // long x = 42;
          // long* a[2];
          // long* b[2] = {&x, &x};
          // memcpy(a, b, sizeof(b)); // both a[0][0] and b[0][0] contain x.
          if (!ValueMap.contains(SrcOp) &&
              mayAliasPointer(SrcOp, MemCopySize, POI)) {
            if (!HandleMemCopy(SrcOp, POI))
              return true; // escaped
          }

          // We're on the receiving end of memcpy/memmove,
          // and aliasing is not detected. Ignore
          continue;
        }
        if (!mayLoadPointer(POI, 0, MemCopySize))
          continue;
        if (!HandleMemCopy(II->getOperand(0), POI))
          return true; // escaped
        continue;
      default:
        // We're not interested in other intrinsics
        break;
      }
    } else if (auto *CB = dyn_cast<CallBase>(Ref)) {
      Function *F = CB->getCalledFunction();
      if (F == nullptr)
        return escaped(VK, ValueEscapeInfo::CallToPtr, VEscTest, CB, &POI);
      StringRef Name = F->getName();
      if (Name == "runtime.typedmemmove") {
        // same as memmove.
        Value *DestOp = getGoCallOperand(CB, 1);
        if (DestOp == VEscTest || POI.empty())
          continue;
        if (HandleMemCopy(DestOp, POI))
          continue;
        return true; // escaped.
      } else if (Name == "runtime.gcWriteBarrier") {
        // This calls indicates object is being copied
        continue;
      } else if (Name == "runtime.gopanic") {
        continue;
      } else {
        // We need to analyze a function argument
        unsigned ArgNo = CB->getArgOperandNo(U);
        if (hasGoStructRetArg(CB, ArgNo))
          continue;
        if (F->isDeclaration()) {
          if (F->getName() == "bcmp")
            continue;
          return escaped(VK, ValueEscapeInfo::CallToUndef, VEscTest, CB, &POI);
        }
        Argument *EscTestArg = F->getArg(ArgNo);
        if (trackEscape(VK_FuncArg, EscTestArg, POI)) {
          const SmallVectorImpl<ValueEscapeInfo>& VEIList = ArgEscapeMap[{EscTestArg, POI}];
          for (auto &VEI : VEIList) {
            if (VEI.LK == ValueEscapeInfo::Returned) {
              if (!AddUses(CB, VEI.POI))
                return true; // escaped;
            } else if (VEI.LK == ValueEscapeInfo::StoreToArg) {
              assert(!VEI.POI.empty());
              unsigned OutArgNo = getFnArgNo(F, VEI.Val);
              assert(OutArgNo != -1U);
              if (!HandleMemCopy(CB->getOperand(OutArgNo), VEI.POI))
                return true;
            } else {
              // Let the escaped function delete argument info, if we've
              // been stucked with recursion, we can't handle.
              auto LK = VEI.LK == ValueEscapeInfo::UnsolvableRecursion
                            ? ValueEscapeInfo::MultipleOffsets
                            : VEI.LK;
              return escaped(VK, LK, VEscTest, VEI.Val, &POI);
            }
          }
        }
      }
    } else if (auto *GEP = dyn_cast<GEPOperator>(Ref)) {
      if (POI.empty()) {
        // For our pointer analysis we consider
        // GCPtr + N to be the same as GCPtr + 0.
        if (!AddUses(GEP, POI))
          return true; // escaped
        continue;
      }
      int64_t GepOffset;
      Value *GepSrc = GEP->getOperand(0);
      assert(ValueMap[GepSrc] == POI);
      if (!getGEPOffset(GEP, GepOffset))
        return escaped(VK, ValueEscapeInfo::GEPOffsetUnknown, VEscTest, GEP,
                       &POI);
      POI.back() -= GepOffset;
      if (!AddUses(GEP, POI))
        return true; // escaped

    } else if (auto *SI = dyn_cast<StoreInst>(Ref)) {
      if (U->getOperandNo() == 1) {
        auto *SrcOp = SI->getOperand(0);
        if (!ValueMap.contains(SrcOp) && mayAliasPointer(SrcOp, 0, POI)) {
          if (!SrcOp->getType()->isVectorTy())
            POI.pop_back();
          if (!HandleMemCopy(SrcOp, POI))
            return true; // escaped
        }
        // any stores to memory addressed by GC pointer or
        // to memory containing GC pointer are ignored
        continue;
      }
      if (!SI->getOperand(0)->getType()->isVectorTy())
        // store ptr, dest is equal to memcpy(dest, &ptr, ptr_size)
        POI.push_back(0);
      if (!HandleMemCopy(SI->getOperand(1), POI))
        return true; // escaped
    } else if (auto *LI = dyn_cast<LoadInst>(Ref)) {
      auto &DL = M.getDataLayout();
      if (POI.empty())
        // loading from object memory is ok
        continue;
      int LdSize = DL.getTypeStoreSize(LI->getType());
      if (!mayLoadPointer(POI, 0, LdSize))
        continue;
      if (!LI->getType()->isVectorTy())
        POI.pop_back();
      if (!AddUses(LI, POI))
        return true; // escape
    } else if (isa<ReturnInst>(Ref)) {
      if (!escaped(VK, ValueEscapeInfo::Returned, VEscTest, Ref, &POI))
        continue;
      return true; // escaped;
    } else if (auto *PTI = dyn_cast<PtrToIntInst>(Ref)) {
      if (!AddUses(PTI, POI))
        return true; // escaped
    } else if (auto *ITP = dyn_cast<IntToPtrInst>(Ref)) {
      if (!AddUses(ITP, POI))
        return true; // escaped
    } else if (auto *IEI = dyn_cast<InsertElementInst>(Ref)) {
      if (U->getOperandNo() == 0)
        continue;
      int64_t N;
      if (!getValueAsConstI64(IEI->getOperand(2), &N))
        return escaped(VK, ValueEscapeInfo::NonConstOperand, VEscTest, IEI,
                       &POI);
      POI.push_back(N * 8); // FIXME
      if (!AddUses(IEI, POI))
        return true; // escape
    } else if (auto *EEI = dyn_cast<ExtractElementInst>(Ref)) {
      int64_t N;
      if (!getValueAsConstI64(EEI->getOperand(2), &N))
        return escaped(VK, ValueEscapeInfo::NonConstOperand, VEscTest, EEI,
                       &POI);
      if (!EEI->getType()->isPointerTy())
        continue;
      if (!mayLoadPointer(POI, 8 * N, PtrSize))
        continue;
      if (!AddUses(EEI, POI))
        return true; // escaped
    } else if (auto *EVI = dyn_cast<ExtractValueInst>(Ref)) {
      Type *StructTy = EVI->getOperand(0)->getType();
      int64_t Off = getOffsetInAggregate(StructTy, EVI->getIndices());
      if (!mayLoadPointer(POI, Off, PtrSize))
        continue;
      assert(POI.back() == Off);
      POI.pop_back();
      if (!AddUses(EVI, POI))
        return true; // escaped
    } else if (auto *IVI = dyn_cast<InsertValueInst>(Ref)) {
      int64_t Off = getOffsetInAggregate(IVI->getType(), IVI->getIndices());
      if (U->getOperandNo() != 0)
        POI.push_back(Off);
      if (!AddUses(IVI, POI))
        return true; // escaped
    } else if (isPassthroughInstruction(Ref)) {
      if (!AddUses(Ref, POI))
        return true; // escaped
    } else if (!shouldIgnore(Ref)) {
      return escaped(VK, ValueEscapeInfo::NotHandledInstr, VEscTest, Ref, &POI);
    }
  }
  return notEscaped(VK, VEscTest);
}

Value *ValueTracker::getGoCallOperand(CallBase *CB, int I) {
  auto Attr =
      CB->getAttributeAtIndex(AttributeList::FirstArgIndex, Attribute::Nest);
  if (Attr.isValid() && isa<PoisonValue>(CB->getOperand(0)))
    return CB->getOperand(I + 1);
  return CB->getOperand(I);
}

bool ValueTracker::getValueAsConstI64(Value *V, int64_t *P) {
  if (auto *CI = dyn_cast<ConstantInt>(V)) {
    *P = CI->getSExtValue();
    return true;
  }
  return false;
}

ValueTracker::ValueEscapeInfo::LeakKind
ValueTracker::identifyStoreTarget(Value *Op, PtrOffsetInfo &POI, Value **V) {
  assert(!POI.empty());
  *V = Op;
  int64_t CurOffset = 0;
  bool addedIndirection = false;
  auto AddIndirectionIfNeeded = [&]() {
    if (addedIndirection)
      return false;
    // instruction -> POI explained:
    // %call = runtime.mallocgc -> {}
    // store %call, %gep -> {0}
    // %gep = getelementptr i8, %tmpv, 8 -> {8}
    // {8} means we can add 8 to value (%tmpv), and then
    // dereference this memory location and get a pointer.
    POI.back() += CurOffset;
    addedIndirection = true;
    return true;
  };
  while (true) {
    if (auto *LI = dyn_cast<LoadInst>(*V)) {
      if (!AddIndirectionIfNeeded())
        POI.push_back(CurOffset);
      CurOffset = 0;
      *V = LI->getOperand(0);
    } else if (auto *GEP = dyn_cast<GEPOperator>(*V)) {
      if (!getGEPOffset(GEP, CurOffset))
        return ValueEscapeInfo::GEPOffsetUnknown;
      *V = GEP->getOperand(0);
    } else {
      break;
    }
  }
  AddIndirectionIfNeeded();
  if (isa<AllocaInst>(*V) || isa<PHINode>(*V) || isa<SelectInst>(*V))
    return ValueEscapeInfo::NotLeaked;

  if (isa<Argument>(*V)) {
    return ValueEscapeInfo::StoreToArg;
  } else if (isa<GlobalVariable>(*V)) {
    return ValueEscapeInfo::StoreToGlobal;
  } else if (auto *CB = dyn_cast<CallBase>(*V)) {
    Function *F = CB->getCalledFunction();
    if (F == nullptr)
      return ValueEscapeInfo::CallToPtr;
    else if (F->isDeclaration())
      return ValueEscapeInfo::CallToUndef;
    else if (!isKnownAllocationFunction(F))
      return ValueEscapeInfo::StoreToEscaped;
  }
  return ValueEscapeInfo::NotLeaked;
}

bool ValueTracker::isPassthroughInstruction(Value *V) {
  auto *I = cast<Instruction>(V);
  switch (I->getOpcode()) {
  case Instruction::PHI:
  case Instruction::Select:
  case Instruction::AddrSpaceCast:
    return true;
  default:
    return false;
  }
}

bool ValueTracker::shouldIgnore(Value *V) {
  auto *I = cast<Instruction>(V);
  switch (I->getOpcode()) {
  case Instruction::ICmp:
    return true;
  default:
    return false;
  }
}

StringRef ValueTracker::leakKindName(int K) {
  switch (K) {
#define DEFINE_GC_LEAK(a, b)                                                   \
  case ValueEscapeInfo::a:                                                     \
    return #a;
#include "GoGcLeakKind.def"
  default:
    llvm_unreachable("type is unknown");
  }
}

LLVM_ATTRIBUTE_USED void
ValueTracker::dumpValueMap(const DenseMap<Value *, PtrOffsetInfo> &ValueMap) {
  for (auto &P : ValueMap) {
    dbgs() << P.second << ": ";
    P.first->print(dbgs());
    dbgs() << "\n";
  }
}

bool ValueTracker::hasArgEscapeInfo(Value* V, const PtrOffsetInfo& POI, bool& Escaped) {  
  Escaped = false;
  auto It = ArgEscapeMap.find({V, POI});
  if (It == ArgEscapeMap.end())
    return false;
  SmallVectorImpl<ValueEscapeInfo>& VEIList = It->second;  
  for (auto &VEI : VEIList) {
    assert(VEI.LK != ValueEscapeInfo::Unknown);
    if (VEI.LK != ValueEscapeInfo::NotLeaked) {
      Escaped = true;
      break;
    }
  }
  return true;
}

// Returns true if we should stop analysis, in such
// case Escaped contains return status
bool ValueTracker::startEscapingAnalysis(ValueKind VK, Value* V, const PtrOffsetInfo& POI, bool& Escaped) {
  Escaped = false;
  if (VK == VK_FuncArg) {    
    if (hasArgEscapeInfo(V, POI, Escaped))
      return true;
    auto P = ArgMap.insert({V, POI});
    if (!P.second) {
      if (P.first->second != POI) {
        Escaped = true;
        return escaped(VK, ValueEscapeInfo::UnsolvableRecursion, V, V, &POI);
      }
      return true;
    }
    ArgEscapeMap[{V, POI}] = {};
  } else {
    ValueEscapeInfo VEI = {ValueEscapeInfo::Unknown, VK, V, {}};
    auto P = ValueEscapeMap.try_emplace(V, VEI);
    if (!P.second) {
      assert(P.first->second.LK != ValueEscapeInfo::Unknown);
      Escaped = (P.first->second.LK != ValueEscapeInfo::NotLeaked);
      return true;
    }
  }
  return false;
}

void ValueTracker::addArgEscapeInfoIfNeeded(
    SmallVectorImpl<ValueEscapeInfo> &VEIList, const ValueEscapeInfo &VI) {
  for (auto &CurVI : VEIList)
    if (CurVI.LK == VI.LK && CurVI.Val == VI.Val && CurVI.POI == VI.POI)
      return;
  VEIList.push_back(VI);
}

bool ValueTracker::escaped(ValueKind VK, ValueEscapeInfo::LeakKind LK, Value *V,
                           Value *S, const PtrOffsetInfo *POI) {
  onEscape(VK, LK, V, S, POI);
  LLVM_DEBUG(dbgs() << "escape: VK = " << VK << " (" << V << ")"
                    << " LK: " << leakKindName(LK) << "\n");
  bool FnArgHasLeaks = false;
  if (VK == VK_FuncArg) {
    auto It = ArgMap.find(V);
    assert(It != ArgMap.end());
    SmallVectorImpl<ValueEscapeInfo> &VEIList = ArgEscapeMap[{V, It->second}];
    FnArgHasLeaks = !VEIList.empty();
    if (LK != ValueEscapeInfo::NotLeaked || !FnArgHasLeaks)
      addArgEscapeInfoIfNeeded(VEIList,
                               {LK, VK, S, POI ? *POI : PtrOffsetInfo()});
    if (LK != ValueEscapeInfo::StoreToArg && LK != ValueEscapeInfo::Returned &&
        LK != ValueEscapeInfo::UnsolvableRecursion)
      ArgMap.erase(It);
    else
      // We don't cancel argument escape analysis with StoreToArg,
      // or Returned escape classes, because caller will investigate
      // such cases further.
      return false;
  } else {
    ValueEscapeMap[V] = {LK, VK, S, POI ? *POI : PtrOffsetInfo()};
  }
  return LK != ValueEscapeInfo::NotLeaked || FnArgHasLeaks;
}

bool ValueTracker::isLoopInvariant(Value *V) {
  if (auto *I = dyn_cast<Instruction>(V)) {
    LoopInfo &LI = FAM.getResult<LoopAnalysis>(*I->getFunction());
    return !LI.getLoopFor(I->getParent());
  }
  return true;
}

bool ValueTracker::mayLoadPointer(const PtrOffsetInfo &POI, unsigned Off,
                                  unsigned Size) {
  if (POI.empty())
    return false;
  unsigned PtrSize = M.getDataLayout().getPointerSize();
  if (Size < PtrSize || POI.back() < 0)
    return false;
  return Off + Size >= POI.back() + PtrSize && Off <= POI.back();
}

bool ValueTracker::mayAliasPointer(Value *Op, int64_t Size,
                                   const PtrOffsetInfo &POI) {
  if (isa<Constant>(Op))
    return false;
  auto &DL = M.getDataLayout();
  if (POI.size() < 2 || POI.back() < 0)
    return false;
  Size = (Size == 0) ? DL.getTypeStoreSize(Op->getType()) : Size;
  return Size >= POI.back() + DL.getPointerSize();
}

void handleInvoke(IRBuilderBase &IRB, Instruction *I) {
  auto *II = dyn_cast<InvokeInst>(I);
  if (II == nullptr)
    return;
  IRB.SetInsertPoint(II->getParent());
  BasicBlock *UnwindBB = II->getUnwindDest();
  if (UnwindBB->getSinglePredecessor()) {
    assert(UnwindBB->getSinglePredecessor() == II->getParent());
    UnwindBB->eraseFromParent();
  } else {
    for (auto &I : *UnwindBB) {
      if (auto *PHI = dyn_cast<PHINode>(&I))
        PHI->removeIncomingValue(II->getParent());
      else
        break;
    }
  }
  BasicBlock *NormBB = II->getNormalDest();
  IRB.CreateBr(NormBB);
}

void removeUnneededFunctionCalls(IRBuilderBase &IRB, AllocaInst *GCStackAlloc) {
  auto Align = GCStackAlloc->getAlign();
  auto *Size = GCStackAlloc->getOperand(0);
  std::vector<Instruction *> ToRemove;
  for (auto &U : GCStackAlloc->uses()) {
    if (auto *Call = dyn_cast<CallBase>(U.getUser())) {
      Function *F = Call->getCalledFunction();
      if (F == nullptr)
        continue;
      if (F->getName() == "runtime.typedmemmove") {
        if (U.getOperandNo() == Call->getNumOperands() - 1)
          continue;
        IRB.SetInsertPoint(Call);
        Value *Src = ValueTracker::getGoCallOperand(Call, 2);
        auto *MemCpy = IRB.CreateMemCpy(U.get(), Align, Src, Align, Size);
        Call->replaceAllUsesWith(MemCpy);
        ToRemove.push_back(Call);
        NumConvertedMemMoves++;
      } else if (F->getName() == "runtime.gcWriteBarrier") {
        ToRemove.push_back(Call);
        NumRemovedGCWB++;
      }
    }
  }
  for (auto *I : ToRemove) {
    handleInvoke(IRB, I);
    I->eraseFromParent();
  }
}

bool optimizeSingleGCAlloc(CallBase *CB) {
  Function *F = CB->getFunction();
  auto SA = ValueTracker::getGoTypeSizeAlignFromCall(CB);
  LLVMContext &C = CB->getContext();
  auto *TyI8 = Type::getInt8Ty(C);
  auto *TyI64 = Type::getInt64Ty(C);
  auto *AllocaSize = ConstantInt::get(TyI64, SA.Size ? SA.Size : 1, false);

  IRBuilder<> IRB(&*F->getEntryBlock().getFirstInsertionPt());
  auto *AllocaInst = IRB.CreateAlloca(TyI8, AllocaSize, "tmpv.gcopt");
  AllocaInst->setAlignment(Align(SA.Align));
  CB->replaceAllUsesWith(AllocaInst);
  if (SA.Size && ValueTracker::allocationZeroesMemory(CB)) {
    IRB.SetInsertPoint(F->getEntryBlock().getTerminator());
    IRB.CreateMemSet(AllocaInst, ConstantInt::get(TyI8, 0), AllocaSize,
                     MaybeAlign(SA.Align));
  }
  // debugging
  if (Function *FnHook = CB->getModule()->getFunction("gcopt.hook")) {
    FunctionCallee Callee(FnHook->getFunctionType(), FnHook);
    IRB.SetInsertPoint(F->getEntryBlock().getTerminator());
    Value *HookArgs[] = {AllocaInst, AllocaSize};
    IRB.CreateCall(Callee, HookArgs);
  }
  handleInvoke(IRB, CB);
  removeUnneededFunctionCalls(IRB, AllocaInst);
  CB->eraseFromParent();
  return true;
}

bool updateModule(Module &M, ModuleAnalysisManager &MAM) {
  bool Changed = false;
  FunctionAnalysisManager &FAM =
      MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
  ValueTracker VT(M, FAM);
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    // if (F.getName() != "main.main")
    //   continue;
    for (BasicBlock &BB : F)
      for (Instruction &I : BB)
        if (auto *CI = dyn_cast<CallBase>(&I))
          if (auto *Fn = dyn_cast<Function>(CI->getCalledOperand())) {
            if (Fn->getName() == "runtime.mallocgc" ||
                Fn->getName() == "runtime.newobject") {
              VT.trackGCPointer(CI);
            }
          }
  }
  for (CallBase *CB : VT.OptimizableGCAllocs)
    Changed |= optimizeSingleGCAlloc(CB);
  VT.updateStats();
  return Changed;
}

} // end anonymous namespace

using PtrOffsetInfo = ValueTracker::PtrOffsetInfo;
template<>
struct llvm::DenseMapInfo<PtrOffsetInfo> {  
  static PtrOffsetInfo getEmptyKey() { return {}; }
  static PtrOffsetInfo getTombstoneKey() { return {{}}; }
  static bool isEqual(const PtrOffsetInfo& POI1, const PtrOffsetInfo& POI2) {
    return POI1 == POI2;
  }
  static unsigned getHashValue(const PtrOffsetInfo& POI) {
    unsigned Res = 0;
    for (auto Off : POI)
      Res ^= DenseMapInfo<PtrOffsetInfo::value_type>::getHashValue(Off);
    return Res;
  }
};

PreservedAnalyses GoGcOptimizePass::run(Module &M, ModuleAnalysisManager &AM) {
  bool Changed = updateModule(M, AM);
  if (!Changed)
    return PreservedAnalyses::all();
  return PreservedAnalyses::none();
}
