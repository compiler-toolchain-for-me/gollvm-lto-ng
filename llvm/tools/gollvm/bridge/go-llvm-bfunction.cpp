//===-- go-llvm-bfunction.cpp - implementation of 'Bfunction' class ---===//
//
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
//
// Methods for class Bfunction.
//
//===----------------------------------------------------------------------===//

#include "go-llvm-bfunction.h"

#include "go-llvm-btype.h"
#include "go-llvm-bstatement.h"
#include "go-llvm-bexpression.h"
#include "go-llvm-bvariable.h"
#include "go-llvm-cabi-oracle.h"
#include "go-llvm-typemanager.h"
#include "go-llvm-irbuilders.h"
#include "go-system.h"

#include "llvm/IR/Argument.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Value.h"

Bfunction::Bfunction(llvm::Constant *fcnValue,
                     BFunctionType *fcnType,
                     const std::string &name,
                     const std::string &asmName,
                     Location location,
                     TypeManager *tm)

    : fcnType_(fcnType), fcnValue_(fcnValue),
      abiOracle_(new CABIOracle(fcnType, tm)),
      rtnValueMem_(nullptr), chainVal_(nullptr),
      paramsRegistered_(0), name_(name), asmName_(asmName),
      location_(location), splitStack_(YesSplit),
      prologGenerated_(false), abiSetupComplete_(false),
      errorSeen_(false)
{
  if (! fcnType->followsCabi())
    abiSetupComplete_ = true;
}

Bfunction::~Bfunction()
{
  if (! prologGenerated_) {
    for (auto ais : allocas_)
      ais->deleteValue();
  }
  for (auto &lab : labels_)
    delete lab;
  for (auto &v : localVariables_) {
    // only delete declvars here, others are in valueVarMap_
    // and will be deleted below.
    if (v->isDeclVar())
      delete v;
  }
  for (auto &kv : valueVarMap_)
    delete kv.second;
  assert(labelAddressPlaceholders_.empty());
}

llvm::Function *Bfunction::function() const
{
  return llvm::cast<llvm::Function>(fcnValue());
}

std::string Bfunction::namegen(const std::string &tag)
{
  return abiOracle_->tm()->tnamegen(tag);
}

llvm::Instruction *Bfunction::addAlloca(Btype *bty, const std::string &name) {
  llvm::Instruction *insBefore = nullptr;
  llvm::Type *typ = bty->type();
  TypeManager *tm = abiOracle_->tm();
  llvm::Align aaAlign = tm->datalayout()->getABITypeAlign(typ);
  llvm::Value *aaSize = nullptr;
  llvm::Instruction *inst = new llvm::AllocaInst(typ, 0, aaSize, aaAlign,
                                                 name, insBefore);
  if (! name.empty())
    inst->setName(name);
  allocas_.push_back(inst);
  return inst;
}

void Bfunction::lazyAbiSetup()
{
  if (abiSetupComplete_)
    return;
  abiSetupComplete_ = true;

  // Populate argument list
  if (arguments_.empty())
    for (auto argit = function()->arg_begin(), argen = function()->arg_end(); argit != argen; ++argit)
      arguments_.push_back(&(*argit));

  // If the return value is going to be passed via memory, make a note
  // of the argument in question, and set up the arg.
  unsigned argIdx = 0;
  if (abiOracle_->returnInfo().disp() == ParmIndirect) {
    std::string sretname(namegen("sret.formal"));
    arguments_[argIdx]->setName(sretname);
    llvm::AttrBuilder SRETAttrs(function()->getContext());
    SRETAttrs.addStructRetAttr(fcnType_->resultType()->type());
    arguments_[argIdx]->addAttrs(SRETAttrs);
    rtnValueMem_ = arguments_[argIdx];
    argIdx += 1;
  }

  // Handle static chain param.  In contrast with real / explicit
  // function params, we don't create the spill slot eagerly.
  assert(abiOracle_->chainInfo().disp() == ParmDirect);
  std::string nestname(namegen("nest"));
  arguments_[argIdx]->setName(nestname);
  arguments_[argIdx]->addAttr(llvm::Attribute::Nest);
  chainVal_ = arguments_[argIdx];
  argIdx += 1;

  // Sort out what to do with each of the parameters.
  const std::vector<Btype *> &paramTypes = fcnType()->paramTypes();
  for (unsigned idx = 0; idx < paramTypes.size(); ++idx) {
    const CABIParamInfo &paramInfo = abiOracle_->paramInfo(idx);
    switch(paramInfo.disp()) {
      case ParmIgnore: {
        // Seems weird to create a zero-sized alloca(), but it should
        // simplify things in that we can avoid having a Bvariable with a
        // null value.
        llvm::Instruction *inst = addAlloca(paramTypes[idx], "");
        paramValues_.push_back(inst);
        break;
      }
      case ParmIndirect: {
        paramValues_.push_back(arguments_[argIdx]);
        assert(paramInfo.numArgSlots() == 1);
        if (paramInfo.attr() == AttrByVal) {
          llvm::AttrBuilder BVAttrs(function()->getContext());
          BVAttrs.addByValAttr(paramTypes[idx]->type());
          arguments_[argIdx]->addAttrs(BVAttrs);
        }
        argIdx += 1;
        break;
      }
      case ParmDirect: {
        llvm::Instruction *inst = addAlloca(paramTypes[idx], "");
        paramValues_.push_back(inst);
        if (paramInfo.attr() == AttrSext)
          arguments_[argIdx]->addAttr(llvm::Attribute::SExt);
        else if (paramInfo.attr() == AttrZext)
          arguments_[argIdx]->addAttr(llvm::Attribute::ZExt);
        else
          assert(paramInfo.attr() == AttrNone);
        argIdx += paramInfo.numArgSlots();
        break;
      }
    }
  }
}

Bvariable *Bfunction::parameterVariable(const std::string &name,
                                        Btype *btype,
                                        bool is_address_taken,
                                        Location location)
{
  lazyAbiSetup();
  unsigned argIdx = paramsRegistered_++;

  // Create Bvariable and install in value->var map.
  llvm::Value *argVal = paramValues_[argIdx];
  assert(valueVarMap_.find(argVal) == valueVarMap_.end());
  Bvariable *bv =
      new Bvariable(btype, location, name, ParamVar, is_address_taken, argVal);
  valueVarMap_[argVal] = bv;

  // Set parameter name or names.
  const CABIParamInfo &paramInfo = abiOracle_->paramInfo(argIdx);
  switch(paramInfo.disp()) {
    case ParmIgnore: {
      std::string iname(name);
      iname += ".ignore";
      paramValues_[argIdx]->setName(name);
      break;
    }
    case ParmIndirect: {
      unsigned soff = paramInfo.sigOffset();
      arguments_[soff]->setName(name);
      break;
    }
    case ParmDirect: {
      unsigned soff = paramInfo.sigOffset();
      if (paramInfo.abiTypes().size() == 1) {
        arguments_[soff]->setName(name);
      } else {
        assert(paramInfo.abiTypes().size() <= CABIParamInfo::ABI_TYPES_MAX_SIZE);
        for (unsigned i = 0; i < paramInfo.abiTypes().size(); ++i) {
          std::string argp = name + ".chunk" + std::to_string(i);
          arguments_[soff+i]->setName(argp);
        }
      }
      std::string aname(name);
      aname += ".addr";
      paramValues_[argIdx]->setName(aname);
    }
  }

  // All done.
  return bv;
}

Bvariable *Bfunction::staticChainVariable(const std::string &name,
                                          Btype *btype,
                                          Location location)
{
  lazyAbiSetup();
  const CABIParamInfo &chainInfo = abiOracle_->chainInfo();
  assert(chainInfo.disp() == ParmDirect);

  // Set name of function parameter
  unsigned soff = chainInfo.sigOffset();
  arguments_[soff]->setName(name);

  // Create the spill slot for the param.
  std::string spname(name);
  spname += ".addr";
  llvm::Instruction *inst = addAlloca(btype, spname);
  assert(chainVal_);
  assert(llvm::isa<llvm::Argument>(chainVal_));
  chainVal_ = inst;

  // Create backend variable to encapsulate the above.
  Bvariable *bv =
      new Bvariable(btype, location, name, ParamVar, false, inst);
  assert(valueVarMap_.find(bv->value()) == valueVarMap_.end());
  valueVarMap_[bv->value()] = bv;

  return bv;
}

Bvariable *Bfunction::localVariable(const std::string &name,
                                    Btype *btype,
                                    Bvariable *declVar,
                                    bool is_address_taken,
                                    Location location)
{
  lazyAbiSetup();
  llvm::Instruction *inst = nullptr;
  if (declVar != nullptr) {
    // If provided, declVar must be an existing local variable in
    // the same function (presumably at an outer scope).
    assert(valueVarMap_.find(declVar->value()) != valueVarMap_.end());

    // For the correct semantics, we need the two variables in question
    // to share the same alloca instruction.
    inst = llvm::cast<llvm::Instruction>(declVar->value());
  } else {
    inst = addAlloca(btype, name);
  }
  if (is_address_taken) {
    llvm::Instruction *alloca = inst;
    if (auto *ascast = llvm::dyn_cast<llvm::AddrSpaceCastInst>(alloca))
      alloca = llvm::cast<llvm::Instruction>(ascast->getPointerOperand());
    alloca->setMetadata("go_addrtaken", llvm::MDNode::get(inst->getContext(), {}));
  }
  Bvariable *bv =
      new Bvariable(btype, location, name, LocalVar, is_address_taken, inst);
  localVariables_.push_back(bv);
  if (declVar != nullptr) {
    // Don't add the variable in question to the value var map.
    // Mark it so that it can be handled properly during creation
    // of lifetime annotations.
    bv->markAsDeclVar();
  } else {
    assert(valueVarMap_.find(bv->value()) == valueVarMap_.end());
    valueVarMap_[bv->value()] = bv;
  }
  return bv;
}

llvm::Value *Bfunction::createTemporary(Btype *btype, const std::string &tag)
{
  return addAlloca(btype, tag);
}

// This implementation uses an alloca instruction as a placeholder
// for a block address.

llvm::Instruction *
Bfunction::createLabelAddressPlaceholder(Btype *btype)
{
  std::string name(namegen("labeladdrplaceholder"));
  TypeManager *tm = abiOracle_->tm();
  llvm::Type *lltype = btype->type();
  llvm::Instruction *insBefore = nullptr;
  llvm::Align aaAlign = tm->datalayout()->getABITypeAlign(lltype);
  llvm::Value *aaSize = nullptr;
  llvm::Instruction *inst = new llvm::AllocaInst(lltype, 0, aaSize, aaAlign,
                                                 name, insBefore);
  labelAddressPlaceholders_.insert(inst);
  return inst;
}

// Called at the point where we have a concrete basic block for
// a Blabel that has had its address taken. Replaces uses of the
// placeholder instruction with the real thing.

void Bfunction::replaceLabelAddressPlaceholder(llvm::Value *placeholder,
                                               llvm::BasicBlock *bbForLabel)
{
  // Locate the PH inst and remove it from the tracking set.
  llvm::Instruction *phinst = llvm::cast<llvm::Instruction>(placeholder);
  auto it = labelAddressPlaceholders_.find(phinst);
  assert(it != labelAddressPlaceholders_.end());
  labelAddressPlaceholders_.erase(it);

  // Create real block address and replace uses of the PH inst with it.
  llvm::BlockAddress *blockad =
      llvm::BlockAddress::get(function(), bbForLabel);
  phinst->replaceAllUsesWith(blockad);

  // Placeholder inst no longer needed.
  phinst->deleteValue();
}

std::vector<Bvariable*> Bfunction::getParameterVars()
{
  std::vector<Bvariable*> res;
  for (auto &argval : paramValues_) {
    auto it = valueVarMap_.find(argval);
    assert(it != valueVarMap_.end());
    Bvariable *v = it->second;
    res.push_back(v);
  }
  return res;
}

std::vector<Bvariable*> Bfunction::getFunctionLocalVars()
{
  return localVariables_;
}

Bvariable *Bfunction::getBvarForValue(llvm::Value *val)
{
  auto it = valueVarMap_.find(val);
  return (it != valueVarMap_.end() ? it->second : nullptr);
}

Bvariable *Bfunction::getNthParamVar(unsigned argIdx)
{
  assert(argIdx < paramValues_.size());
  llvm::Value *pval = paramValues_[argIdx];
  return getBvarForValue(pval);
}

unsigned Bfunction::genArgSpill(Bvariable *paramVar,
                                const CABIParamInfo &paramInfo,
                                Binstructions *spillInstructions,
                                llvm::Value *sploc)
{
  lazyAbiSetup();
  assert(paramInfo.disp() == ParmDirect);
  TypeManager *tm = abiOracle_->tm();
  BlockLIRBuilder builder(function(), this);

  // Simple case: param arrived in single register.
  if (paramInfo.abiTypes().size() == 1) {
    llvm::Argument *arg = arguments_[paramInfo.sigOffset()];
    assert(sploc->getType()->isPointerTy());
    llvm::PointerType *llpt = llvm::cast<llvm::PointerType>(sploc->getType());
    llvm::Instruction *si = builder.CreateStore(arg, sploc);
    paramVar->setInitializer(si);
    spillInstructions->appendInstructions(builder.instructions());
    return 1;
  }

  assert(paramInfo.abiTypes().size() <= CABIParamInfo::ABI_TYPES_MAX_SIZE);
  // More complex case: param arrives in multiple registers.

  // Create struct type corresponding to multiple params.
  llvm::Type *llst = paramInfo.computeABIStructType(tm);
  llvm::Type *ptst = llvm::PointerType::get(llst, 0);

  // Cast the spill location to a pointer to the struct created above.
  std::string tag(namegen("cast"));
  llvm::Value *bitcast = builder.CreateBitCast(sploc, ptst, tag);
  llvm::Instruction *stinst = nullptr;

  // Generate a store to each field.
  for (unsigned i = 0; i < paramInfo.abiTypes().size(); ++i) {
    std::string tag(namegen("field" + std::to_string(i)));
    llvm::Value *fieldgep =
        builder.CreateConstInBoundsGEP2_32(llst, bitcast, 0, i, tag);
    llvm::Value *argChunk = arguments_[paramInfo.sigOffset() + i];
    stinst = builder.CreateStore(argChunk, fieldgep);
  }
  paramVar->setInitializer(stinst);
  spillInstructions->appendInstructions(builder.instructions());

  // All done.
  return paramInfo.abiTypes().size();
}

void Bfunction::genProlog(llvm::BasicBlock *entry)
{
  lazyAbiSetup();
  unsigned argIdx = (abiOracle_->returnInfo().disp() == ParmIndirect ? 1 : 0);
  Binstructions spills;

  // Spill the static chain param if needed. We only want to do this
  // if a chain variable was explicitly requested.
  const CABIParamInfo &chainInfo = abiOracle_->chainInfo();
  assert(chainInfo.disp() == ParmDirect);
  unsigned soff = chainInfo.sigOffset();
  if (arguments_[soff] != chainVal_) {
    auto it = valueVarMap_.find(chainVal_);
    assert(it != valueVarMap_.end());
    Bvariable *chainVar = it->second;
    genArgSpill(chainVar, chainInfo, &spills, chainVal_);
  }
  argIdx += 1;

  // Spill any directly-passed function arguments into their previous
  // created spill areas.
  const std::vector<Btype *> &paramTypes = fcnType()->paramTypes();
  unsigned nParms = paramTypes.size();
  for (unsigned pidx = 0; pidx < nParms; ++pidx) {
    const CABIParamInfo &paramInfo = abiOracle_->paramInfo(pidx);
    if (paramInfo.disp() != ParmDirect)
      continue;
    Bvariable *v = getNthParamVar(pidx);
    if (!v) {
      assert(errorSeen());
      continue;
    }
    llvm::Value *sploc = llvm::cast<llvm::Instruction>(paramValues_[pidx]);
    argIdx += genArgSpill(v, paramInfo, &spills, sploc);
  }

  // Append allocas for local variables
  // FIXME: create lifetime annotations
  for (auto aa : allocas_)
    aa->insertBefore(*entry, entry->end());

  // Param spills
  for (auto sp : spills.instructions())
    sp->insertBefore(*entry, entry->end());

  // Debug meta-data generation needs to know the position at which a
  // parameter variable is available for inspection -- this is
  // typically either A) the start of the function for by-address
  // params, or B) the spill instruction that copies a direct param to
  // the stack. If the entry block is not empty, then use the last
  // inst in it as an initializer for by-address params. If the block
  // is still empty at this point we'll take care of things later.
  if (! entry->empty()) {
    for (unsigned pidx = 0; pidx < nParms; ++pidx) {
      Bvariable *v = getNthParamVar(pidx);
      if (!v) {
        assert(errorSeen());
        continue;
      }
      if (v->initializer() == nullptr)
        v->setInitializer(&entry->front());
    }
  }

  prologGenerated_ = true;
}

void Bfunction::fixupProlog(llvm::BasicBlock *entry,
                            const std::vector<llvm::Instruction *> &temps)
{
  lazyAbiSetup();
  // If there are any "new" temporaries discovered during the control
  // flow generation walk, incorporate them into the entry block. At this
  // stage in the game the entry block is already fully populated, including
  // (potentially) references to the alloca instructions themselves, so
  // we insert any new temps into the start of the block.
  if (! temps.empty())
    for (auto ai : temps) {
      ai->insertInto(entry, entry->begin());
      if (auto *ascast = llvm::dyn_cast<llvm::AddrSpaceCastInst>(ai)) {
        llvm::Value *op = ascast->getPointerOperand();
        assert(llvm::isa<llvm::AllocaInst>(op));
        llvm::cast<llvm::Instruction>(op)->insertInto(entry, entry->begin());
      }
    }
}

llvm::Value *Bfunction::genReturnSequence(Bexpression *toRet,
                                          Binstructions *retInstrs,
                                          NameGen *inamegen)
{
  lazyAbiSetup();
  const CABIParamInfo &returnInfo = abiOracle_->returnInfo();

  // If we're returning an empty struct, or if the function has void
  // type, then return a null ptr (return "void").
  TypeManager *tm = abiOracle_->tm();
  if (returnInfo.disp() == ParmIgnore ||
      fcnType()->resultType()->type() == tm->llvmVoidType()) {
    llvm::Value *rval = nullptr;
    return rval;
  }

  // Indirect return: emit memcpy into sret
  if (returnInfo.disp() == ParmIndirect) {
    BlockLIRBuilder bbuilder(function(), inamegen);
    uint64_t sz = tm->typeSize(fcnType_->resultType());
    uint64_t algn = tm->typeAlignment(fcnType_->resultType());
    llvm::MaybeAlign malgn(algn);
    bbuilder.CreateMemCpy(rtnValueMem_, malgn, toRet->value(), malgn, sz);
    retInstrs->appendInstructions(bbuilder.instructions());
    llvm::Value *rval = nullptr;
    return rval;
  }

  // Direct return: single value
  if (! returnInfo.abiType()->isAggregateType() &&
      ! toRet->btype()->type()->isAggregateType())
    return toRet->value();

  // Direct return: either the ABI type is a structure or the
  // return value type is a structure. In this case we bitcast
  // the return location address to the ABI type and then issue a load
  // from the bitcast.
  llvm::Type *llrt = (returnInfo.abiType()->isAggregateType() ?
                      returnInfo.computeABIStructType(tm) :
                      returnInfo.abiType());
  llvm::Type *ptst = llvm::PointerType::get(llrt, 0);
  BlockLIRBuilder builder(function(), inamegen);
  std::string castname(namegen("cast"));
  llvm::Value *bitcast = builder.CreateBitCast(toRet->value(), ptst, castname);
  std::string loadname(namegen("ld"));
  llvm::Instruction *ldinst = builder.CreateLoad(llrt, bitcast, loadname);
  retInstrs->appendInstructions(builder.instructions());
  return ldinst;
}

Blabel *Bfunction::newLabel(Location loc) {
  unsigned labelCount = labels_.size();
  Blabel *lb = new Blabel(this, labelCount, loc);
  labelmap_.push_back(nullptr);
  labels_.push_back(lb);
  return lb;
}

void Bfunction::registerLabelDefStatement(Bstatement *st, Blabel *label)
{
  assert(st && st->flavor() == N_LabelStmt);
  assert(label);
  assert(labelmap_[label->label()] == nullptr);
  labelmap_[label->label()] = st;
}
