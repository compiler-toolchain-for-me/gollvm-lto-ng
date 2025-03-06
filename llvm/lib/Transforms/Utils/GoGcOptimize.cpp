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

#include <array>
#include <set>

using namespace llvm;

namespace {

////////////////////////////////////////////////////////////////////
class ValueTracker {
public:
  enum ValueKind { VK_GCPointer, VK_FuncArg };

  typedef SmallVector<unsigned, 4> PtrOffsetInfo;

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
      StoreToUnknown,
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

  bool escapedByUnhandledInst(ValueKind VK, Value *V, Value *S) {
    return escaped(VK, ValueEscapeInfo::NotHandledInstr, V, S);
  }
  bool escapedByNonConstOperand(ValueKind VK, Value *V, Value *S) {
    return escaped(VK, ValueEscapeInfo::NonConstOperand, V, S);
  }
  bool escapedByNotLoopInvariant(ValueKind VK, Value *V) {
    return escaped(VK, ValueEscapeInfo::NotLoopInvariant, V, nullptr);
  }
  bool escapedByCallToFuncPtr(ValueKind VK, Value *V, Value *S) {
    return escaped(VK, ValueEscapeInfo::CallToPtr, V, S);
  }
  bool escapedByCallToUndef(ValueKind VK, Value *V, Value *S) {
    return escaped(VK, ValueEscapeInfo::CallToUndef, V, S);
  }
  bool escapedByUnsolvableRecursion(ValueKind VK, Value *V, const PtrOffsetInfo& POI) {
    return escaped(VK, ValueEscapeInfo::UnsolvableRecursion, V, nullptr, &POI);
  }
  bool escapedByUnknownGEPOffset(ValueKind VK, Value *V, Value *S) {
    auto &SE = FAM->getResult<ScalarEvolutionAnalysis>(
        *cast<Instruction>(S)->getFunction());
    auto *SCEV = SE.removePointerBase(SE.getSCEV(S));
    SCEV->dump();
    return escaped(VK, ValueEscapeInfo::GEPOffsetUnknown, V, S);
  }
  bool escapedByStoreToEscaped(ValueKind VK, Value *V, Value *S) {
    return escaped(VK, ValueEscapeInfo::StoreToEscaped, V, S);
  }
  bool escapedByStoreToUnknown(ValueKind VK, Value *V, Value *S) {
    return escaped(VK, ValueEscapeInfo::StoreToUnknown, V, S);
  }
  bool escapedByReturn(ValueKind VK, Value *V, Value *S,
                       const PtrOffsetInfo *POI) {
    return escaped(VK, ValueEscapeInfo::Returned, V, S, POI);
  }
  bool escapedByStoreToArg(ValueKind VK, Value *V, Value *S,
                           const PtrOffsetInfo *POI) {
    return escaped(VK, ValueEscapeInfo::StoreToArg, V, S, POI);
  }
  bool escapedByStoreToGlobal(ValueKind VK, Value *V, Value *S) {
    return escaped(VK, ValueEscapeInfo::StoreToGlobal, V, S);
  }
  bool escapedByMultipleOffsets(ValueKind VK, Value *V, Value *S,
                                const PtrOffsetInfo *POI) {
    return escaped(VK, ValueEscapeInfo::MultipleOffsets, V, S, POI);
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
  Value *identifyStoreTarget(Value *Op, PtrOffsetInfo &POI);
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
  bool getGEPOffset(Value *GEP, unsigned &Offset);
  unsigned getOffsetInAggregate(Type *TyAgg, ArrayRef<unsigned> Indices);
  static void dumpPtrOffsetInfo(const PtrOffsetInfo &POI) {
    dbgs() << "{";
    for (unsigned I = 0; I < POI.size(); ++I) {
      dbgs() << POI[I];
      if (I < POI.size() - 1)
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

bool ValueTracker::getGEPOffset(Value *V, unsigned &Offset) {
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
      escapedByMultipleOffsets(VK, VEscTest, V, &POI);
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
        if (!isLoopInvariant(STV)) {
          escapedByNotLoopInvariant(VK, VEscTest);
          return false;
        }
        PtrOffsetInfo POI = ValuePOI;
        if (Value *V = identifyStoreTarget(STV, POI)) {
          if (auto *A = dyn_cast<Argument>(V)) {
            escapedByStoreToArg(VK, VEscTest, A, &POI);
            return VK == VK_FuncArg;
          } else if (auto *GV = dyn_cast<GlobalVariable>(V)) {
            escapedByStoreToGlobal(VK, VEscTest, GV);
            return false;
          } else if (auto *PHI = dyn_cast<PHINode>(V)) {
            for (auto &IV : PHI->incoming_values())
              if (!HandleMemCopy(IV.get(), POI))
                return false;
            return true;
          } else if (auto *GEP = dyn_cast<GEPOperator>(V)) {
            escapedByUnknownGEPOffset(VK, VEscTest, GEP);
            return false;
          } else if (auto *F = dyn_cast<Function>(V)) {            
            if (F->isDeclaration())
              escapedByCallToUndef(VK, VEscTest, F);
            else              
              escapedByStoreToEscaped(VK, VEscTest, F);
            return false;
          } else if (auto *SelI = dyn_cast<SelectInst>(V)) {
            return HandleMemCopy(SelI->getOperand(1), POI) &&
                   HandleMemCopy(SelI->getOperand(2), POI);
          }
          return AddUses(V, POI);
        }
        escapedByStoreToUnknown(VK, VEscTest, STV);
        return false;
      };

  if (VK == VK_GCPointer)
    if (!isLoopInvariant(VEscTest))
      return escapedByNotLoopInvariant(VK, VEscTest);

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
        if (getValueAsConstI64(II->getOperand(2), &MemCopySize))
          if (MemCopySize <= POI.back())
            continue;
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
        return escapedByCallToFuncPtr(VK, VEscTest, CB);
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
          return escapedByCallToUndef(VK, VEscTest, CB);
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
              return escaped(VK, VEI.LK, VEscTest, CB, &POI);
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
      unsigned GepOffset;
      Value *GepSrc = GEP->getOperand(0);
      assert(ValueMap[GepSrc] == POI);
      if (!getGEPOffset(GEP, GepOffset))
        return escapedByUnknownGEPOffset(VK, VEscTest, GEP);
      if (POI.back() >= GepOffset) {
        if (!subtractOffset(POI.back(), GepOffset))
          continue;        
        if (!AddUses(GEP, POI))
          return true; // escaped
      }
    } else if (auto *SI = dyn_cast<StoreInst>(Ref)) {
      if (U->getOperandNo() == 1)
        // any stores to memory addressed by GC pointer or
        // to memory containing GC pointer are ignored
        continue;
      if (!SI->getOperand(0)->getType()->isVectorTy())
        // store ptr, dest is equal to memcpy(dest, &ptr, ptr_size)
        POI.push_back(0);
      if (HandleMemCopy(SI->getOperand(1), POI))
        continue;
      return true;
    } else if (auto *LI = dyn_cast<LoadInst>(Ref)) {
      auto &DL = M.getDataLayout();
      if (POI.empty())
        // loading from object memory is ok
        continue;
      unsigned LdSize = DL.getTypeStoreSize(LI->getType());
      unsigned PtrSize = DL.getPointerSize();
      if (LdSize <= POI.back())
        continue;
      if (LdSize < PtrSize + POI.back())
        continue;
      if (!LI->getType()->isVectorTy())
        POI.pop_back();
      if (!AddUses(LI, POI))
        return true; // escape
    } else if (isa<ReturnInst>(Ref)) {
      escapedByReturn(VK, VEscTest, Ref, &POI);
      if (VK == VK_FuncArg)
        continue;
      return true;
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
        return escapedByNonConstOperand(VK, VEscTest, IEI);
      POI.push_back(N * 8);
      if (!AddUses(IEI, POI))
        return true; // escape
    } else if (auto *EEI = dyn_cast<ExtractElementInst>(Ref)) {
      int64_t N;
      if (!getValueAsConstI64(EEI->getOperand(2), &N))
        return escapedByNonConstOperand(VK, VEscTest, EEI);
      if (POI.back() != 8 * N)
        continue;
      if (!AddUses(EEI, POI))
        return true; // escaped
    } else if (auto *EVI = dyn_cast<ExtractValueInst>(Ref)) {
      Type *StructTy = EVI->getOperand(0)->getType();
      int64_t Off = getOffsetInAggregate(StructTy, EVI->getIndices());
      if (Off == POI.back()) {
        POI.pop_back();
        if (!AddUses(EVI, POI))
          return true; // escaped
      }
    } else if (auto *IVI = dyn_cast<InsertValueInst>(Ref)) {
      if (U->getOperandNo() == 0)
        continue;
      int64_t Off = getOffsetInAggregate(IVI->getType(), IVI->getIndices());
      POI.push_back(Off);
      if (!AddUses(IVI, POI))
        return true; // escaped
    } else if (isPassthroughInstruction(Ref)) {
      if (!AddUses(Ref, POI))
        return true; // escaped
    } else if (!shouldIgnore(Ref)) {
      return escapedByUnhandledInst(VK, VEscTest, Ref);
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

Value *ValueTracker::identifyStoreTarget(Value *Op, PtrOffsetInfo &POI) {
  assert(!POI.empty());
  Value *Dest = Op;
  unsigned CurOffset = 0;
  bool addedIndirection = false;
  auto AddIndirectionIfNeeded = [&]() {
    if (addedIndirection)
      return false;
    POI.back() += CurOffset;
    addedIndirection = true;
    return true;
  };
  while (true) {
    if (auto *LI = dyn_cast<LoadInst>(Dest)) {
      if (!AddIndirectionIfNeeded())
        POI.push_back(CurOffset);
      CurOffset = 0;
      Dest = LI->getOperand(0);
    } else if (auto *GEP = dyn_cast<GEPOperator>(Dest)) {
      if (!getGEPOffset(GEP, CurOffset))
        return GEP;
      Dest = GEP->getOperand(0);
    } else if (auto *ITP = dyn_cast<IntToPtrInst>(Dest)) {
      Dest = ITP->getOperand(0);
    } else {
      break;
    }
  }
  AddIndirectionIfNeeded();
  if (isa<AllocaInst>(Dest) || isa<Argument>(Dest) || isa<GlobalVariable>(Dest) ||
      isa<PHINode>(Dest) || isa<SelectInst>(Dest))
    return Dest;
  if (auto *CB = dyn_cast<CallBase>(Dest)) {
    Function *F = CB->getCalledFunction();
    if (F == nullptr)
      return nullptr;
    if (trackReturnValue(F))
      return F;
    
    return Dest;
  }
  return nullptr;
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
  case ValueEscapeInfo::StoreToUnknown:
    return "StoreToUnknown";
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
        return escapedByUnsolvableRecursion(VK, V, POI);
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

bool ValueTracker::escaped(ValueKind VK, ValueEscapeInfo::LeakKind LK, Value *V,
                           Value *S, const PtrOffsetInfo *POI) {
  // if (LK == ValueEscapeInfo::NotHandledInstr) {
  //    S->dump();
  //  }
  bool FnArgEscaped = false;
  if (VK == VK_FuncArg) {
    auto It = ArgMap.find(V);
    assert(It != ArgMap.end());
    SmallVectorImpl<ValueEscapeInfo> &VEIList = ArgEscapeMap[{V, It->second}];
    FnArgEscaped = !VEIList.empty();
    if (LK != ValueEscapeInfo::NotLeaked || !FnArgEscaped)
      ArgEscapeMap[{V, It->second}].push_back(
          {LK, VK, S, POI ? *POI : PtrOffsetInfo()});
    if (LK != ValueEscapeInfo::StoreToArg && LK != ValueEscapeInfo::Returned)
      ArgMap.erase(It);
  } else {
    ValueEscapeMap[V] = {LK, VK, S, POI ? *POI : PtrOffsetInfo()};
  }
  return LK != ValueEscapeInfo::NotLeaked || FnArgEscaped;
}

} // end anonymous namespace

using PtrOffsetInfo = ValueTracker::PtrOffsetInfo;
template<>
struct llvm::DenseMapInfo<PtrOffsetInfo> {  
  static PtrOffsetInfo getEmptyKey() { return {}; }
  static PtrOffsetInfo getTombstoneKey() { return {-2U}; }
  static bool isEqual(const PtrOffsetInfo& POI1, const PtrOffsetInfo& POI2) {
    return POI1 == POI2;
  }
  static unsigned getHashValue(const PtrOffsetInfo& POI) {
    unsigned Res = 0;
    for (auto Off : POI)
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
