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
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/ScalarEvolution.h"
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

using namespace llvm;

namespace {
////////////////////////////////////////////////////////////////////
class ValueTracker {
public:
  enum ValueKind { VK_GCPointer, VK_FuncArg };

  typedef SmallVector<int64_t, 2> SCEVCoeffList;
  typedef SmallVector<SCEVCoeffList, 2> PtrOffsetInfo;

  ValueTracker(Module &Mod) : M(Mod) {}

  bool trackGCPointer(Value *V);
  void printStats();
  void setFAM(FunctionAnalysisManager &FAM) { this->FAM = &FAM; }

private:
  struct ValueEscapeInfo {
    enum LeakKind : uint32_t {
      NotLeaked,
      Unknown,
      StoreToGlobal,
      StoreToArg,
      StoreToEscaped,
      NotHandledInstr,
      GEPOffsetUnknown,
      CallToUndef,
      Returned,
      MultipleOffsets,
      CallToPtr,
      UnsolvableRecursion,
      NonConstOperand,
      NotLoopInvariant,
      _LastKind
    };
    LeakKind LK;
    ValueKind VK;
    Value *Val;
    PtrOffsetInfo POI;
  };

  bool trackEscape(ValueKind VK, Value *V, const PtrOffsetInfo &POI);

  static Value *getGoCallOperand(CallBase *CB, int I);
  static bool getValueAsConstI64(Value *V, int64_t *P);
  static bool isPassthroughInstruction(Value *V);
  static bool shouldIgnore(Value *V);
  StringRef leakKindName(int K);

  void onEscape(ValueKind VK, ValueEscapeInfo::LeakKind LK, Value *V, Value *S,
                const PtrOffsetInfo *POI) {
    if (LK != ValueEscapeInfo::GEPOffsetUnknown)
      return;
#if 0
    auto &SE = FAM->getResult<ScalarEvolutionAnalysis>(
        *cast<Instruction>(S)->getFunction());
    auto *SCEV = SE.removePointerBase(SE.getSCEV(S));
    SCEV->dump();
#endif
  }

  bool notEscaped(ValueKind VK, Value *V) {
    return escaped(VK, ValueEscapeInfo::NotLeaked, V, nullptr);
  }
  bool hasArgEscapeInfo(Value* V, const PtrOffsetInfo& POI, bool& Escaped);

  // Returns true if we should stop analysis, in such
  // case Escaped contains return status
  bool startEscapingAnalysis(ValueKind VK, Value* V, const PtrOffsetInfo& POI, bool& Escaped);
  bool escaped(ValueKind VK, ValueEscapeInfo::LeakKind LK, Value *V, Value *S,
               const PtrOffsetInfo *POI = nullptr);

  bool getLeakKind(Value *V, ValueEscapeInfo::LeakKind &LK);
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
  bool trackReturnValue(Function *F);
  bool getGEPOffset(Value *GEP, int &Offset);
  unsigned getOffsetInAggregate(Type *TyAgg, ArrayRef<unsigned> Indices);

  static void dump(int64_t V) { dbgs() << V; }
  template <class T> static void dump(const SmallVectorImpl<T> &Vec) {
    dbgs() << "{";
    for (unsigned I = 0; I < Vec.size(); ++I) {
      dump(Vec[I]);
      if (I < Vec.size() - 1)
        dbgs() << ",";
    }
    dbgs() << "}";
  }

  bool isLoopInvariant(Value *V) {
    if (auto *I = dyn_cast<Instruction>(V)) {
      LoopInfo &LI = FAM->getResult<LoopAnalysis>(*I->getFunction());
      return !LI.getLoopFor(I->getParent());
    }
    return true;
  }

  unsigned mayLoadPointer(unsigned Offset, unsigned Size,
                          const PtrOffsetInfo &POI) {
    unsigned PtrSize = M.getDataLayout().getPointerSize();
    unsigned Ret = 0;
    SCEVCoeffList CL = POI.back();
    CL[0] -= Offset;
    for (unsigned I = 0; I < Size / PtrSize; ++I) {
      // Offset += I * PtrSize;
      // SCEVCoeffList CL = subtractSCEV(POI.back(), {Offset});
      // assert(CL == CL2);
      if (CL.size() == 1) {
        if (CL[0] == 0)
          Ret |= (1 << I);
      } else {
        int GCD = gcd(CL);
        if (CL[0] % GCD == 0)
          Ret |= (1 << I);
      }
      CL[0] -= PtrSize;
    }
    return Ret;
  }

  SCEVCoeffList subtractSCEV(const SCEVCoeffList &A, const SCEVCoeffList &B) {
    size_t I;
    SCEVCoeffList Result;
    Result.push_back(A[0] - B[0]);
    for (I = 1; I < A.size(); ++I)
      Result.push_back(A[I]);
    for (I = 1; I < B.size(); ++I)
      Result.push_back(-B[I]);
    return Result;
  }

  int gcd(const SCEVCoeffList &CL) {
    assert(CL.size() > 1);
    int GCD = std::abs(CL[1]);
    for (size_t I = 2; I < CL.size(); ++I)
      GCD = std::gcd(GCD, CL[I]);
    return GCD;
  }

  static bool isPowerOf2(unsigned V) { return (V & (V - 1)) == 0; }

  Module &M;
  DenseMap<Value *, ValueEscapeInfo> ValueEscapeMap;  
  DenseMap<std::pair<Value*, PtrOffsetInfo>, SmallVector<ValueEscapeInfo, 4>> ArgEscapeMap;
  DenseMap<Value*, PtrOffsetInfo> ArgMap;
  DenseMap<StringRef, unsigned> CallStats;
  FunctionAnalysisManager *FAM;
};

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
  static const char *Names[] = {"runtime.mallocgc", "runtime.newobject",
                                "runtime.makeslice"};
  for (unsigned I = 0; I < sizeof(Names) / sizeof(Names[0]); ++I)
    if (Name == Names[I])
      return true;
  return false;
}

bool ValueTracker::getLeakKind(Value *V, ValueEscapeInfo::LeakKind &LK) {  
  LK = ValueEscapeInfo::Unknown;
  auto It = ValueEscapeMap.find(V);
  if (It == ValueEscapeMap.end())
    return false;
  LK = It->second.LK;
  return true;
}

bool ValueTracker::getGEPOffset(Value *V, int &Offset) {
  auto *GEP = cast<GEPOperator>(V);
  APInt APOffset(M.getDataLayout().getIndexTypeSizeInBits(GEP->getType()), 0);
  if (!GEP->accumulateConstantOffset(M.getDataLayout(), APOffset))
    return false;
  Offset = APOffset.getZExtValue();
  return true;
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
  CallStats[CB->getCalledFunction()->getName()]++;
  return trackEscape(VK_GCPointer, V, {});
}

void ValueTracker::printStats() {
  SmallVector<unsigned, 16> GCCounts(ValueEscapeInfo::_LastKind);
  SmallVector<unsigned, 16> FACounts(ValueEscapeInfo::_LastKind);
  dbgs() << "GC CALLS PROCESSED:\n";
  for (auto &P : CallStats)
    dbgs() << P.first << ": " << P.second << "\n";
  dbgs() << "\n";
  unsigned GCTotal = 0;
  for (auto &P : ValueEscapeMap) {
    GCCounts[P.second.LK]++;
    GCTotal++;
  }
  dbgs() << "GC OBJECT STATS, TOTAL: " << GCTotal << ":\n";
  for (unsigned I = 0; I < GCCounts.size(); ++I) {
    dbgs() << leakKindName(I) << " : " << GCCounts[I] << "\n";
  }
  dbgs() << "\n";
  for (auto &P : ArgEscapeMap) {
    for (auto &VEI : P.second)
      FACounts[VEI.LK]++;
  }
  dbgs() << "FUNC ARG STATS:\n";
  for (unsigned I = 0; I < FACounts.size(); ++I) {
    dbgs() << leakKindName(I) << " : " << FACounts[I] << "\n";
  }
}

bool ValueTracker::trackEscape(ValueKind VK, Value *VEscTest,
                               const PtrOffsetInfo &POI) {
  SmallVector<Use *, 16> Worklist;
  DenseSet<Use *> Seen;
  DenseMap<Value *, PtrOffsetInfo> ValueMap;
  auto AddUses = [&](Value *V, const PtrOffsetInfo &POI) {
    auto VIt = ValueMap.find(V);
    if (VIt != ValueMap.end() && VIt->second != POI) {
      escaped(VK, ValueEscapeInfo::MultipleOffsets, VEscTest, V, &POI);
      return false;
    }
    for (auto &U : V->uses())
      if (!Seen.contains(&U)) {
        ValueMap[V] = POI;
        Seen.insert(&U);
        Worklist.push_back(&U);
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

  if (VK == VK_GCPointer)
    if (!isLoopInvariant(VEscTest))
      return escaped(VK, ValueEscapeInfo::NotLoopInvariant, VEscTest, VEscTest,
                     &POI);

  bool Escaped;
  if (startEscapingAnalysis(VK, VEscTest, POI, Escaped))
    return Escaped;
  if (!AddUses(VEscTest, POI))
    return true;

  while (!Worklist.empty()) {
    Use *U = Worklist.back();
    assert(ValueMap.contains(U->get()));
    PtrOffsetInfo POI = ValueMap[U->get()];
    Worklist.pop_back();
    User *Ref = U->getUser();
    if (auto *II = dyn_cast<IntrinsicInst>(Ref)) {
      switch (II->getIntrinsicID()) {
      case Intrinsic::memcpy:
      case Intrinsic::memmove:
        if (POI.empty())
          // we're reading or writing contents of our object
          // not copying pointer itself.
          continue;
        if (U->get() == II->getOperand(0))
          // We're on the receiving end of memcpy/memmove, ignore
          continue;
        int64_t MemCopySize;
        // If amount to be copied is too small then ignore it
        if (getValueAsConstI64(II->getOperand(2), &MemCopySize)) {
          unsigned LoadRes = mayLoadPointer(0, MemCopySize, POI);
          if (LoadRes == 0)
            continue;
          if (!isPowerOf2(LoadRes))
            return escaped(VK, ValueEscapeInfo::MultipleOffsets, VEscTest, II,
                           &POI);
        }
        if (HandleMemCopy(II->getOperand(0), POI))
          continue;
        return true; // escaped
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
              return escaped(VK, VEI.LK, VEscTest, VEI.Val, &POI);
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
      int GepOffset;
      Value *GepSrc = GEP->getOperand(0);
      assert(ValueMap[GepSrc] == POI);
      if (!getGEPOffset(GEP, GepOffset))
        return escaped(VK, ValueEscapeInfo::GEPOffsetUnknown, VEscTest, GEP,
                       &POI);
      SCEVCoeffList CL = subtractSCEV(POI.back(), {GepOffset});
      POI.back() = CL;
      if (!AddUses(GEP, POI))
        return true; // escaped

    } else if (auto *SI = dyn_cast<StoreInst>(Ref)) {
      if (U->getOperandNo() == 1)
        // any stores to memory addressed by GC pointer or
        // to memory containing GC pointer are ignored
        continue;
      if (!SI->getOperand(0)->getType()->isVectorTy())
        // store ptr, dest is equal to memcpy(dest, &ptr, ptr_size)
        POI.push_back({0});
      if (HandleMemCopy(SI->getOperand(1), POI))
        continue;
      return true;
    } else if (auto *LI = dyn_cast<LoadInst>(Ref)) {
      auto &DL = M.getDataLayout();
      if (POI.empty())
        // loading from object memory is ok
        continue;

      unsigned LdSize = DL.getTypeStoreSize(LI->getType());
      unsigned LdStatus = mayLoadPointer(0, LdSize, POI);
      if (LdStatus == 0)
        continue;
      if (!isPowerOf2(LdStatus))
        return escaped(VK, ValueEscapeInfo::MultipleOffsets, VEscTest, Ref,
                       &POI);
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
      POI.push_back({N * 8}); // FIXME
      if (!AddUses(IEI, POI))
        return true; // escape
    } else if (auto *EEI = dyn_cast<ExtractElementInst>(Ref)) {
      int64_t N;
      if (!getValueAsConstI64(EEI->getOperand(2), &N))
        return escaped(VK, ValueEscapeInfo::NonConstOperand, VEscTest, EEI,
                       &POI);
      if (!EEI->getType()->isPointerTy())
        continue;
      unsigned PtrSize = M.getDataLayout().getPointerSize();
      if (!mayLoadPointer(N * 8, PtrSize, POI))
        continue;
      if (!AddUses(EEI, POI))
        return true; // escaped
    } else if (auto *EVI = dyn_cast<ExtractValueInst>(Ref)) {
      Type *StructTy = EVI->getOperand(0)->getType();
      int64_t Off = getOffsetInAggregate(StructTy, EVI->getIndices());
      if (POI.back() == SCEVCoeffList{Off}) {
        POI.pop_back();
        if (!AddUses(EVI, POI))
          return true; // escaped
      }
    } else if (auto *IVI = dyn_cast<InsertValueInst>(Ref)) {
      if (U->getOperandNo() == 0)
        continue;
      int64_t Off = getOffsetInAggregate(IVI->getType(), IVI->getIndices());
      POI.push_back({Off}); // FIXME
      if (!AddUses(IVI, POI))
        return true; // escaped
    } else if (isPassthroughInstruction(Ref)) {
      if (!AddUses(Ref, POI))
        return true; // escaped
    } else if (!shouldIgnore(Ref)) {
      return escaped(VK, ValueEscapeInfo::NotHandledInstr, VEscTest, Ref);
    }
  }
  return notEscaped(VK, VEscTest);
}

bool ValueTracker::trackReturnValue(Function *F) {
  if (isKnownAllocationFunction(F))
    return false;
  if (F->isDeclaration())
    return true;
  for (auto &BB : *F) {
    if (auto *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
      if (auto *CB = dyn_cast<CallBase>(RI->getOperand(0))) {
        if (isKnownAllocationFunction(CB->getCalledFunction()) ||
            !trackReturnValue(CB->getCalledFunction()))
          continue;
      }
      return true;
    }
  }  
  return false;
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
  int CurOffset = 0;
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
    POI.back()[0] += CurOffset;
    addedIndirection = true;
    return true;
  };
  while (true) {
    if (auto *LI = dyn_cast<LoadInst>(*V)) {
      if (!AddIndirectionIfNeeded())
        POI.push_back({CurOffset});
      CurOffset = 0;
      *V = LI->getOperand(0);
    } else if (auto *GEP = dyn_cast<GEPOperator>(*V)) {
      if (!getGEPOffset(GEP, CurOffset))
        return ValueEscapeInfo::GEPOffsetUnknown;
      *V = GEP->getOperand(0);
    } else if (auto *ITP = dyn_cast<IntToPtrInst>(*V)) {
      *V = ITP->getOperand(0);
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
    else if (trackReturnValue(F))
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
  case ValueEscapeInfo::NotLeaked:
    return "NotLeaked";
  case ValueEscapeInfo::Unknown:
    return "Unknown";
  case ValueEscapeInfo::StoreToGlobal:
    return "StoreToGlobal";
  case ValueEscapeInfo::StoreToArg:
    return "StoreToArg";
  case ValueEscapeInfo::StoreToEscaped:
    return "StoreToEscaped";
  case ValueEscapeInfo::NotHandledInstr:
    return "NotHandledInstr";
  case ValueEscapeInfo::GEPOffsetUnknown:
    return "GEPOffsetUnknown";
  case ValueEscapeInfo::CallToUndef:
    return "CallToUndef";
  case ValueEscapeInfo::Returned:
    return "Returned";
  case ValueEscapeInfo::MultipleOffsets:
    return "MultipleOffsets";
  case ValueEscapeInfo::CallToPtr:
    return "CallToPtr";
  case ValueEscapeInfo::UnsolvableRecursion:
    return "UnsolvableRecursion";
  case ValueEscapeInfo::NonConstOperand:
    return "NonConstOperand";
  case ValueEscapeInfo::NotLoopInvariant:
    return "NotLoopInvariant";
  default:
    llvm_unreachable("type is unknown");
  }
}

bool updateModule(Module &M, ModuleAnalysisManager &MAM) {
  bool Changed = false;
  ValueTracker VT(M);
  for (Function &F : M) {
    if (F.isDeclaration())
      continue;
    // if (F.getName() != "main.main")
    // continue;
    FunctionAnalysisManager &FAM =
        MAM.getResult<FunctionAnalysisManagerModuleProxy>(M).getManager();
    VT.setFAM(FAM);
    for (BasicBlock &BB : F) {
      for (Instruction &I : BB) {
        if (auto *CI = dyn_cast<CallBase>(&I)) {
          if (auto *Fn = dyn_cast<Function>(CI->getCalledOperand())) {
            if (Fn->getName() == "runtime.mallocgc" ||
                Fn->getName() == "runtime.newobject") {
              VT.trackGCPointer(CI);
            }
          }
        }
      }
    }
  }
  VT.printStats();
  return Changed;
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
    if (!P.second)
      if (P.first->second != POI) {
        Escaped = true;
        return escaped(VK, ValueEscapeInfo::UnsolvableRecursion, V, V, &POI);
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
  if (VK == VK_FuncArg) {
    auto It = ArgMap.find(V);
    assert(It != ArgMap.end());
    SmallVectorImpl<ValueEscapeInfo> &VEIList = ArgEscapeMap[{V, It->second}];
    if (LK != ValueEscapeInfo::NotLeaked || VEIList.empty())
      addArgEscapeInfoIfNeeded(VEIList,
                               {LK, VK, S, POI ? *POI : PtrOffsetInfo()});
    if (LK != ValueEscapeInfo::StoreToArg && LK != ValueEscapeInfo::Returned)
      ArgMap.erase(It);
    else
      // We don't cancel argument escape analysis with StoreToArg,
      // or Returned escape classes, because caller will investigate
      // such cases further.
      return false;
  } else {
    ValueEscapeMap[V] = {LK, VK, S, POI ? *POI : PtrOffsetInfo()};
  }
  return LK != ValueEscapeInfo::NotLeaked;
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
    for (auto L : POI)
      for (auto Off : L)
        Res ^= DenseMapInfo<unsigned>::getHashValue(Off);
    return Res;
  }
};

PreservedAnalyses GoGcOptimizePass::run(Module &M, ModuleAnalysisManager &AM) {
  bool Changed = updateModule(M, AM);
  if (!Changed)
    return PreservedAnalyses::all();
  return PreservedAnalyses::none();
}
