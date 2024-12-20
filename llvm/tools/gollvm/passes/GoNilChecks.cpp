//===- GoNilChecks.cpp - Fold nil checks into memory accesses -----===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This pass turns explicit null checks of the form
//
//   test %r10, %r10
//   je call_panic
//   movl (%r10), %esi
//   ...
//
// to
//
//   movl (%r10), %esi
//   ...
//
// With an exception table entry that covers the load/store instruction.
//
//===----------------------------------------------------------------------===//

#include "GollvmPasses.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/MemoryLocation.h"
#include "llvm/CodeGen/FaultMaps.h"
#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstr.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineMemOperand.h"
#include "llvm/CodeGen/MachineOperand.h"
#include "llvm/CodeGen/MachineRegisterInfo.h"
#include "llvm/CodeGen/PseudoSourceValue.h"
#include "llvm/CodeGen/TargetInstrInfo.h"
#include "llvm/CodeGen/TargetOpcodes.h"
#include "llvm/CodeGen/TargetRegisterInfo.h"
#include "llvm/CodeGen/TargetSubtargetInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DebugLoc.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/MC/MCContext.h"
#include "llvm/MC/MCInstrDesc.h"
#include "llvm/MC/MCRegisterInfo.h"
#include "llvm/Pass.h"
#include "llvm/InitializePasses.h"
#include "llvm/Support/CommandLine.h"
#include <cassert>
#include <cstdint>
#include <iterator>

using namespace llvm;

static cl::opt<bool> Disabled("disable-go-nil-check",
                              cl::desc("Disable Go implicit nil check pass"),
                              cl::init(false), cl::Hidden);

static cl::opt<int> PageSize("go-nil-check-page-size",
                             cl::desc("The page size of the target in bytes"),
                             cl::init(4096), cl::Hidden);

static cl::opt<unsigned> MaxInstsToConsider(
    "go-nil-max-insts-to-consider",
    cl::desc("The max number of instructions to consider hoisting loads over "
             "(the algorithm is quadratic over this number)"),
    cl::Hidden, cl::init(8));

#define DEBUG_TYPE "go-nil-checks"

STATISTIC(NumImplicitNullChecks,
          "Number of explicit null checks made implicit");

namespace {

class GoNilChecks : public MachineFunctionPass {
  /// Return true if \c computeDependence can process \p MI.
  static bool canHandle(const MachineInstr *MI);

  /// Helper function for \c computeDependence.  Return true if \p A
  /// and \p B do not have any dependences between them, and can be
  /// re-ordered without changing program semantics.
  bool canReorder(const MachineInstr *A, const MachineInstr *B);

  /// A data type for representing the result computed by \c
  /// computeDependence.  States whether it is okay to reorder the
  /// instruction passed to \c computeDependence with at most one
  /// dependency.
  struct DependenceResult {
    /// Can we actually re-order \p MI with \p Insts (see \c
    /// computeDependence).
    bool CanReorder;

    /// If non-None, then an instruction in \p Insts that also must be
    /// hoisted.
    std::optional<ArrayRef<MachineInstr *>::iterator> PotentialDependence;

    /*implicit*/ DependenceResult(
        bool CanReorder,
        std::optional<ArrayRef<MachineInstr *>::iterator> PotentialDependence)
        : CanReorder(CanReorder), PotentialDependence(PotentialDependence) {
      assert((!PotentialDependence || CanReorder) &&
             "!CanReorder && PotentialDependence.hasValue() not allowed!");
    }
  };

  /// Compute a result for the following question: can \p MI be
  /// re-ordered from after \p Insts to before it.
  ///
  /// \c canHandle should return true for all instructions in \p
  /// Insts.
  DependenceResult computeDependence(const MachineInstr *MI,
                                     ArrayRef<MachineInstr *> Block);

  /// Represents one null check that can be made implicit.
  class NullCheck {
    // The memory operation the null check can be folded into.
    MachineInstr *MemOperation;

    // The instruction actually doing the null check (Ptr != 0).
    MachineInstr *CheckOperation;

    // The block the check resides in.
    MachineBasicBlock *CheckBlock;

    // The block branched to if the pointer is non-null.
    MachineBasicBlock *NotNullSucc;

    // The block branched to if the pointer is null.
    MachineBasicBlock *NullSucc;

    // If this is non-null, then MemOperation has a dependency on this
    // instruction; and it needs to be hoisted to execute before MemOperation.
    MachineInstr *OnlyDependency;

  public:
    explicit NullCheck(MachineInstr *memOperation, MachineInstr *checkOperation,
                       MachineBasicBlock *checkBlock,
                       MachineBasicBlock *notNullSucc,
                       MachineBasicBlock *nullSucc,
                       MachineInstr *onlyDependency)
        : MemOperation(memOperation), CheckOperation(checkOperation),
          CheckBlock(checkBlock), NotNullSucc(notNullSucc), NullSucc(nullSucc),
          OnlyDependency(onlyDependency) {}

    MachineInstr *getMemOperation() const { return MemOperation; }

    MachineInstr *getCheckOperation() const { return CheckOperation; }

    MachineBasicBlock *getCheckBlock() const { return CheckBlock; }

    MachineBasicBlock *getNotNullSucc() const { return NotNullSucc; }

    MachineBasicBlock *getNullSucc() const { return NullSucc; }

    MachineInstr *getOnlyDependency() const { return OnlyDependency; }
  };

  const TargetInstrInfo *TII = nullptr;
  const TargetRegisterInfo *TRI = nullptr;
  AliasAnalysis *AA = nullptr;
  MachineFrameInfo *MFI = nullptr;

  bool analyzeBlockForNullChecks(MachineBasicBlock &MBB,
                                 SmallVectorImpl<NullCheck> &NullCheckList);
  void rewriteNullChecks(ArrayRef<NullCheck> NullCheckList);
  void insertLandingPad(MachineInstr *FaultMI, MachineBasicBlock *FaultBB);

  enum AliasResult {
    AR_NoAlias,
    AR_MayAlias,
    AR_WillAliasEverything
  };

  /// Returns AR_NoAlias if \p MI memory operation does not alias with
  /// \p PrevMI, AR_MayAlias if they may alias and AR_WillAliasEverything if
  /// they may alias and any further memory operation may alias with \p PrevMI.
  AliasResult areMemoryOpsAliased(const MachineInstr &MI,
                                  const MachineInstr *PrevMI) const;

  enum SuitabilityResult {
    SR_Suitable,
    SR_Unsuitable,
    SR_Impossible
  };

  /// Return SR_Suitable if \p MI a memory operation that can be used to
  /// implicitly null check the value in \p PointerReg, SR_Unsuitable if
  /// \p MI cannot be used to null check and SR_Impossible if there is
  /// no sense to continue lookup due to any other instruction will not be able
  /// to be used. \p PrevInsts is the set of instruction seen since
  /// the explicit null check on \p PointerReg.
  SuitabilityResult isSuitableMemoryOp(const MachineInstr &MI,
                                       unsigned PointerReg,
                                       ArrayRef<MachineInstr *> PrevInsts);

  /// Return true if \p FaultingMI can be hoisted from after the
  /// instructions in \p InstsSeenSoFar to before them.  Set \p Dependence to a
  /// non-null value if we also need to (and legally can) hoist a depedency.
  bool canHoistInst(MachineInstr *FaultingMI, unsigned PointerReg,
                    ArrayRef<MachineInstr *> InstsSeenSoFar,
                    MachineBasicBlock *NullSucc, MachineInstr *&Dependence);

public:
  static char ID;

  GoNilChecks() : MachineFunctionPass(ID) {
    initializeGoNilChecksPass(*PassRegistry::getPassRegistry());
  }

  bool runOnMachineFunction(MachineFunction &MF) override;

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<AAResultsWrapperPass>();
    MachineFunctionPass::getAnalysisUsage(AU);
  }

  MachineFunctionProperties getRequiredProperties() const override {
    return MachineFunctionProperties().set(
        MachineFunctionProperties::Property::NoVRegs);
  }
};

} // end anonymous namespace

bool GoNilChecks::canHandle(const MachineInstr *MI) {
  if (MI->isCall() || MI->mayRaiseFPException() ||
      MI->hasUnmodeledSideEffects())
    return false;
  auto IsRegMask = [](const MachineOperand &MO) { return MO.isRegMask(); };
  (void)IsRegMask;

  assert(!llvm::any_of(MI->operands(), IsRegMask) &&
         "Calls were filtered out above!");

  auto IsUnordered = [](MachineMemOperand *MMO) { return MMO->isUnordered(); };
  return llvm::all_of(MI->memoperands(), IsUnordered);
}

GoNilChecks::DependenceResult
GoNilChecks::computeDependence(const MachineInstr *MI,
                               ArrayRef<MachineInstr *> Block) {
  assert(llvm::all_of(Block, canHandle) && "Check this first!");
  assert(!is_contained(Block, MI) && "Block must be exclusive of MI!");

  std::optional<ArrayRef<MachineInstr *>::iterator> Dep;

  for (auto I = Block.begin(), E = Block.end(); I != E; ++I) {
    if (canReorder(*I, MI))
      continue;

    if (!Dep.has_value()) {
      // Found one possible dependency, keep track of it.
      Dep = I;
    } else {
      // We found two dependencies, so bail out.
      return {false, {}};
    }
  }

  return {true, Dep};
}

bool GoNilChecks::canReorder(const MachineInstr *A,
                                    const MachineInstr *B) {
  assert(canHandle(A) && canHandle(B) && "Precondition!");

  // canHandle makes sure that we _can_ correctly analyze the dependencies
  // between A and B here -- for instance, we should not be dealing with heap
  // load-store dependencies here.

  for (auto MOA : A->operands()) {
    if (!(MOA.isReg() && MOA.getReg()))
      continue;

    unsigned RegA = MOA.getReg();
    for (auto MOB : B->operands()) {
      if (!(MOB.isReg() && MOB.getReg()))
        continue;

      unsigned RegB = MOB.getReg();

      if (TRI->regsOverlap(RegA, RegB) && (MOA.isDef() || MOB.isDef()))
        return false;
    }
  }

  return true;
}

bool GoNilChecks::runOnMachineFunction(MachineFunction &MF) {
  if (Disabled)
    return false;

  TII = MF.getSubtarget().getInstrInfo();
  TRI = MF.getRegInfo().getTargetRegisterInfo();
  MFI = &MF.getFrameInfo();
  AA = &getAnalysis<AAResultsWrapperPass>().getAAResults();

  SmallVector<NullCheck, 16> NullCheckList;

  for (auto &MBB : MF)
    analyzeBlockForNullChecks(MBB, NullCheckList);

  if (!NullCheckList.empty())
    rewriteNullChecks(NullCheckList);

  return !NullCheckList.empty();
}

// Return true if any register aliasing \p Reg is live-in into \p MBB.
static bool AnyAliasLiveIn(const TargetRegisterInfo *TRI,
                           MachineBasicBlock *MBB, unsigned Reg) {
  for (MCRegAliasIterator AR(Reg, TRI, /*IncludeSelf*/ true); AR.isValid();
       ++AR)
    if (MBB->isLiveIn(*AR))
      return true;
  return false;
}

GoNilChecks::AliasResult
GoNilChecks::areMemoryOpsAliased(const MachineInstr &MI,
                                 const MachineInstr *PrevMI) const {
  // If it is not memory access, skip the check.
  if (!(PrevMI->mayStore() || PrevMI->mayLoad()))
    return AR_NoAlias;
  // Load-Load may alias
  if (!(MI.mayStore() || PrevMI->mayStore()))
    return AR_NoAlias;
  // We lost info, conservatively alias. If it was store then no sense to
  // continue because we won't be able to check against it further.
  if (MI.memoperands_empty())
    return MI.mayStore() ? AR_WillAliasEverything : AR_MayAlias;
  if (PrevMI->memoperands_empty())
    return PrevMI->mayStore() ? AR_WillAliasEverything : AR_MayAlias;

  for (MachineMemOperand *MMO1 : MI.memoperands()) {
    // Original code asserts MMO1->getValue() is not null. But it actually
    // can be, e.g. in the call sequence of preparing a byval arg.
    // It is very rare to get here, only when there is a store between the
    // nil check and the load. Maybe we can do better, but just be
    // conservative for now.
    if (!MMO1->getValue())
      return AR_MayAlias;
    for (MachineMemOperand *MMO2 : PrevMI->memoperands()) {
      if (const PseudoSourceValue *PSV = MMO2->getPseudoValue()) {
        if (PSV->mayAlias(MFI))
          return AR_MayAlias;
        continue;
      }
      llvm::AliasResult AAResult = AA->alias(
          MemoryLocation::getAfter(MMO1->getValue(), MMO1->getAAInfo()),
          MemoryLocation::getAfter(MMO2->getValue(), MMO2->getAAInfo()));
      if (AAResult != llvm::AliasResult::NoAlias)
        return AR_MayAlias;
    }
  }
  return AR_NoAlias;
}

GoNilChecks::SuitabilityResult
GoNilChecks::isSuitableMemoryOp(const MachineInstr &MI,
                                unsigned PointerReg,
                                ArrayRef<MachineInstr *> PrevInsts) {
  int64_t Offset;
  const MachineOperand *BaseOp;
  bool OffsetIsScalable;

  if (!TII->getMemOperandWithOffset(MI, BaseOp, Offset, OffsetIsScalable, TRI) ||
      !BaseOp->isReg() || BaseOp->getReg() != PointerReg)
    return SR_Unsuitable;

  // FIXME: This algorithm assumes instructions have fixed-size offsets.
  if (OffsetIsScalable)
    return SR_Unsuitable;

  // We want the mem access to be issued at a sane offset from PointerReg,
  // so that if PointerReg is null then the access reliably page faults.
  if (!((MI.mayLoad() || MI.mayStore()) && !MI.isPredicable() &&
        -PageSize < Offset && Offset < PageSize))
    return SR_Unsuitable;

  // Finally, check whether the current memory access aliases with previous one.
  for (auto *PrevMI : PrevInsts) {
    AliasResult AR = areMemoryOpsAliased(MI, PrevMI);
    if (AR == AR_WillAliasEverything)
      return SR_Impossible;
    if (AR == AR_MayAlias)
      return SR_Unsuitable;
  }
  return SR_Suitable;
}

bool GoNilChecks::canHoistInst(MachineInstr *FaultingMI,
                               unsigned PointerReg,
                               ArrayRef<MachineInstr *> InstsSeenSoFar,
                               MachineBasicBlock *NullSucc,
                               MachineInstr *&Dependence) {
  auto DepResult = computeDependence(FaultingMI, InstsSeenSoFar);
  if (!DepResult.CanReorder)
    return false;

  if (!DepResult.PotentialDependence) {
    Dependence = nullptr;
    return true;
  }

  auto DependenceItr = *DepResult.PotentialDependence;
  auto *DependenceMI = *DependenceItr;

  // We don't want to reason about speculating loads.  Note -- at this point
  // we should have already filtered out all of the other non-speculatable
  // things, like calls and stores.
  // We also do not want to hoist stores because it might change the memory
  // while the FaultingMI may result in faulting.
  assert(canHandle(DependenceMI) && "Should never have reached here!");
  if (DependenceMI->mayLoadOrStore())
    return false;

  for (auto &DependenceMO : DependenceMI->operands()) {
    if (!(DependenceMO.isReg() && DependenceMO.getReg()))
      continue;

    // Make sure that we won't clobber any live ins to the sibling block by
    // hoisting Dependency.  For instance, we can't hoist INST to before the
    // null check (even if it safe, and does not violate any dependencies in
    // the non_null_block) if %rdx is live in to _null_block.
    //
    //    test %rcx, %rcx
    //    je _null_block
    //  _non_null_block:
    //    %rdx = INST
    //    ...
    //
    // This restriction does not apply to the faulting load inst because in
    // case the pointer loaded from is in the null page, the load will not
    // semantically execute, and affect machine state.  That is, if the load
    // was loading into %rax and it faults, the value of %rax should stay the
    // same as it would have been had the load not have executed and we'd have
    // branched to NullSucc directly.
    if (AnyAliasLiveIn(TRI, NullSucc, DependenceMO.getReg()))
      return false;

    // The Dependency can't be re-defining the base register -- then we won't
    // get the memory operation on the address we want.  This is already
    // checked in \c IsSuitableMemoryOp.
    assert(!(DependenceMO.isDef() &&
             TRI->regsOverlap(DependenceMO.getReg(), PointerReg)) &&
           "Should have been checked before!");
  }

  auto DepDepResult =
      computeDependence(DependenceMI, {InstsSeenSoFar.begin(), DependenceItr});

  if (!DepDepResult.CanReorder || DepDepResult.PotentialDependence)
    return false;

  Dependence = DependenceMI;
  return true;
}

/// Analyze MBB to check if its terminating branch can be turned into an
/// implicit null check.  If yes, append a description of the said null check to
/// NullCheckList and return true, else return false.
bool GoNilChecks::analyzeBlockForNullChecks(
    MachineBasicBlock &MBB, SmallVectorImpl<NullCheck> &NullCheckList) {
  using MachineBranchPredicate = TargetInstrInfo::MachineBranchPredicate;

  MDNode *BranchMD = nullptr;
  if (auto *BB = MBB.getBasicBlock())
    BranchMD = BB->getTerminator()->getMetadata(LLVMContext::MD_make_implicit);

  if (!BranchMD)
    return false;

  MachineBranchPredicate MBP;

  if (TII->analyzeBranchPredicate(MBB, MBP, true))
    return false;

  // Is the predicate comparing an integer to zero?
  if (!(MBP.LHS.isReg() && MBP.RHS.isImm() && MBP.RHS.getImm() == 0 &&
        (MBP.Predicate == MachineBranchPredicate::PRED_NE ||
         MBP.Predicate == MachineBranchPredicate::PRED_EQ)))
    return false;

  // If we cannot erase the test instruction itself, then making the null check
  // implicit does not buy us much.
  if (!MBP.SingleUseCondition)
    return false;

  MachineBasicBlock *NotNullSucc, *NullSucc;

  if (MBP.Predicate == MachineBranchPredicate::PRED_NE) {
    NotNullSucc = MBP.TrueDest;
    NullSucc = MBP.FalseDest;
  } else {
    NotNullSucc = MBP.FalseDest;
    NullSucc = MBP.TrueDest;
  }

  // We handle the simplest case for now.  We can potentially do better by using
  // the machine dominator tree.
  if (NotNullSucc->pred_size() != 1)
    return false;

  // To prevent the invalid transformation of the following code:
  //
  //   mov %rax, %rcx
  //   test %rax, %rax
  //   %rax = ...
  //   je throw_npe
  //   mov(%rcx), %r9
  //   mov(%rax), %r10
  //
  // into:
  //
  //   mov %rax, %rcx
  //   %rax = ....
  //   movl (%rax), %r10  // if fault, goto throw_npe
  //   mov(%rcx), %r9
  //
  // we must ensure that there are no instructions between the 'test' and
  // conditional jump that modify %rax.
  const unsigned PointerReg = MBP.LHS.getReg();

  assert(MBP.ConditionDef->getParent() ==  &MBB && "Should be in basic block");

  for (auto I = MBB.rbegin(); MBP.ConditionDef != &*I; ++I)
    if (I->modifiesRegister(PointerReg, TRI))
      return false;

  // Starting with a code fragment like:
  //
  //   test %rax, %rax
  //   jne LblNotNull
  //
  //  LblNull:
  //   callq throw_NullPointerException
  //
  //  LblNotNull:
  //   Inst0
  //   Inst1
  //   ...
  //   Def = Load (%rax + <offset>)
  //   ...
  //
  //
  // we want to end up with
  //
  //   Def = FaultingLoad (%rax + <offset>), LblNull
  //   jmp LblNotNull ;; explicit or fallthrough
  //
  //  LblNotNull:
  //   Inst0
  //   Inst1
  //   ...
  //
  //  LblNull:
  //   callq throw_NullPointerException
  //
  //
  // To see why this is legal, consider the two possibilities:
  //
  //  1. %rax is null: since we constrain <offset> to be less than PageSize, the
  //     load instruction dereferences the null page, causing a segmentation
  //     fault.
  //
  //  2. %rax is not null: in this case we know that the load cannot fault, as
  //     otherwise the load would've faulted in the original program too and the
  //     original program would've been undefined.
  //
  // This reasoning cannot be extended to justify hoisting through arbitrary
  // control flow.  For instance, in the example below (in pseudo-C)
  //
  //    if (ptr == null) { throw_npe(); unreachable; }
  //    if (some_cond) { return 42; }
  //    v = ptr->field;  // LD
  //    ...
  //
  // we cannot (without code duplication) use the load marked "LD" to null check
  // ptr -- clause (2) above does not apply in this case.  In the above program
  // the safety of ptr->field can be dependent on some_cond; and, for instance,
  // ptr could be some non-null invalid reference that never gets loaded from
  // because some_cond is always true.

  SmallVector<MachineInstr *, 8> InstsSeenSoFar;

  for (auto &MI : *NotNullSucc) {
    if (!canHandle(&MI) || InstsSeenSoFar.size() >= MaxInstsToConsider)
      return false;

    MachineInstr *Dependence;
    SuitabilityResult SR = isSuitableMemoryOp(MI, PointerReg, InstsSeenSoFar);
    if (SR == SR_Impossible)
      return false;
    if (SR == SR_Suitable &&
        canHoistInst(&MI, PointerReg, InstsSeenSoFar, NullSucc, Dependence)) {
      NullCheckList.emplace_back(&MI, MBP.ConditionDef, &MBB, NotNullSucc,
                                 NullSucc, Dependence);
      return true;
    }

    // If MI re-defines the PointerReg then we cannot move further.
    if (llvm::any_of(MI.operands(), [&](MachineOperand &MO) {
          return MO.isReg() && MO.getReg() && MO.isDef() &&
                 TRI->regsOverlap(MO.getReg(), PointerReg);
        }))
      return false;
    InstsSeenSoFar.push_back(&MI);
  }

  return false;
}

/// Rewrite the null checks in NullCheckList into implicit null checks.
void
GoNilChecks::rewriteNullChecks(
    ArrayRef<GoNilChecks::NullCheck> NullCheckList) {
  DebugLoc DL;

  for (auto &NC : NullCheckList) {
    // Remove the conditional branch dependent on the null check.
    unsigned BranchesRemoved = TII->removeBranch(*NC.getCheckBlock());
    (void)BranchesRemoved;
    assert(BranchesRemoved > 0 && "expected at least one branch!");

    MachineBasicBlock* CheckBB = NC.getCheckBlock();

    if (auto *DepMI = NC.getOnlyDependency()) {
      DepMI->removeFromParent();
      CheckBB->insert(CheckBB->end(), DepMI);
    }

    // Insert a faulting instruction where the conditional branch was
    // originally. We check earlier ensures that this bit of code motion
    // is legal.  We do not touch the successors list for any basic block
    // since we haven't changed control flow, we've just made it implicit.
    MachineInstr *FaultMI = NC.getMemOperation();
    FaultMI->removeFromParent();
    CheckBB->insert(CheckBB->end(), FaultMI);

    NC.getCheckOperation()->eraseFromParent();

    // Insert an *unconditional* branch to not-null successor.
    if (!CheckBB->isLayoutSuccessor(NC.getNotNullSucc()))
      TII->insertBranch(*CheckBB, NC.getNotNullSucc(), nullptr,
                        /*Cond=*/{}, DL);

    NumImplicitNullChecks++;

    if (!FaultMI->getMF()->getLandingPads().empty())
      insertLandingPad(FaultMI, NC.getNullSucc());
  }
}

/// Add an exception table entry covering the faulting instruction.
void
GoNilChecks::insertLandingPad(MachineInstr *FaultMI,
                              MachineBasicBlock *FaultBB) {

  MachineFunction *MF = FaultBB->getParent();
  MCContext &Context = MF->getContext();
  auto &EHLabelDesc = TII->get(TargetOpcode::EH_LABEL);
  DebugLoc DL;

  // The expected control flow is:
  //
  //   load/store // handler: faultBB
  //   ...
  // faultBB:
  //   invoke runtime.panicmem() unwind label padBB
  // padBB:
  //   exception handler
  //
  // We need to find padBB.
  if (!FaultBB->isEHPad()) {
    MachineBasicBlock *PadBB = nullptr;
    for (auto SI = FaultBB->succ_begin(), SE = FaultBB->succ_end(); SI != SE; ++SI)
      if ((*SI)->isEHPad()) {
        PadBB = *SI;
        break;
      }
    if (!PadBB)
      // The original panic is not supposed to be caught in this frame.
      // We don't need to catch the segfault either.
      return;

    // Create a landing pad.
    FaultBB->setIsEHPad();
    LandingPadInfo &LP = MF->getOrCreateLandingPadInfo(FaultBB);
    MCSymbol *FaultSym;
    if (FaultBB->front().isEHLabel())
      FaultSym = FaultBB->front().getOperand(0).getMCSymbol();
    else {
      FaultSym = Context.createTempSymbol();
      BuildMI(*FaultBB, FaultBB->begin(), DebugLoc(), EHLabelDesc).addSym(FaultSym);
    }
    LP.LandingPadLabel = FaultSym;
    LP.TypeIds = MF->getOrCreateLandingPadInfo(PadBB).TypeIds;

    // Tricky:
    // The original semantics of https://llvm.org/docs/FaultMaps.html
    // is that when the fault happens, the signal handler will jump to
    // faultBB, which will raise an exception.
    // In the Go runtime the signal handler itself raises the exception.
    // We get here when the exception is already raised. Don't raise
    // again. Just jump to the actual exception handler.
    // We cannot directly put padBB in the exception table, as we want
    // to execute the instructions in faultBB first (except the panic
    // call).
    for (MachineInstr &MI : *FaultBB)
      if (MI.isCall() && MI.getOperand(0).isGlobal() &&
          MI.getOperand(0).getGlobal()->getName() == "runtime.panicmem") {
        MI.eraseFromParent();
        break;
      }
    TII->insertBranch(*FaultBB, PadBB, nullptr, {}, DL);
  }

  // Add EH labels before and after the faulting op.
  MachineBasicBlock *MBB = FaultMI->getParent();
  MCSymbol *BeginSym = Context.createTempSymbol();
  BuildMI(*MBB, FaultMI, DL, EHLabelDesc).addSym(BeginSym);

  MCSymbol *EndSym = Context.createTempSymbol();
  BuildMI(*MBB, ++FaultMI->getIterator(), DL, EHLabelDesc).addSym(EndSym);

  // Add exception table entry.
  MF->addInvoke(FaultBB, BeginSym, EndSym);
}

char GoNilChecks::ID = 0;

INITIALIZE_PASS_BEGIN(GoNilChecks, DEBUG_TYPE,
                      "Make nil checks implicit", false, false)
INITIALIZE_PASS_DEPENDENCY(AAResultsWrapperPass)
INITIALIZE_PASS_END(GoNilChecks, DEBUG_TYPE,
                    "Make nil checks implicit", false, false)

FunctionPass *llvm::createGoNilChecksPass() { return new GoNilChecks(); }
