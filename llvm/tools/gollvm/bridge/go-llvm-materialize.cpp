//===-- go-llvm-materialize.cpp - Llvm_backend materalize* methods  -------===//
//
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
//
// Llvm_backend methods relating to materialization of llvm values.
//
//===----------------------------------------------------------------------===//

#include "go-llvm.h"
#include "go-llvm-builtins.h"
#include "go-c.h"
#include "go-system.h"
#include "go-llvm-cabi-oracle.h"
#include "go-llvm-irbuilders.h"
#include "gogo.h"

#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DIBuilder.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/IR/InlineAsm.h"

static llvm::cl::opt<bool> DisableInlineGetg("disable-inline-getg",
                                             llvm::cl::desc("Disable inlining getg"),
                                             llvm::cl::init(false),
                                             llvm::cl::Hidden);

Bexpression *Llvm_backend::materializeIndirect(Bexpression *indExpr, bool isLHS)
{
  Location location = indExpr->location();
  Btype *btype = indExpr->btype();
  std::vector<Bexpression *> iexprs =
      nbuilder_.extractChildenAndDestroy(indExpr);
  assert(iexprs.size() == 1);
  Bexpression *expr = iexprs[0];

  // Handle cases such as
  //
  //    *(*sometype)(unsafe.Pointer(uintptr(<constant>))) = ...
  //
  // where we have a LHS expression intended to cause a crash or fault.
  if (isLHS && !expr->varExprPending()) {
    Bexpression *rval = nbuilder_.mkDeref(btype, expr->value(), expr,
                                          location);
    return rval;
  }

  const VarContext *vc = nullptr;
  if (expr->varExprPending()) {
    vc = &expr->varContext();
    // handle *&x
    if (vc->addrLevel() != 0) {
      Bexpression *rval = nbuilder_.mkDeref(btype, expr->value(), expr,
                                            location);
      rval->setVarExprPending(vc->lvalue(), vc->addrLevel() - 1);
      return rval;
    }
  }

  std::string tag(expr->tag().size() == 0 ? "deref" : expr->tag());
  Bexpression *rval = genLoad(expr, btype, location, tag);
  if (vc) {
    if (rval->varExprPending())
      rval->resetVarExprContext();
    rval->setVarExprPending(expr->varContext());
  }

  return rval;
}

Bexpression *Llvm_backend::materializeAddress(Bexpression *addrExpr)
{
  Location location = addrExpr->location();
  std::vector<Bexpression *> aexprs =
      nbuilder_.extractChildenAndDestroy(addrExpr);
  Bexpression *bexpr = aexprs[0];
  assert(aexprs.size() == 1);
  assert(bexpr->value());

  // Gofrontend tends to take the address of things that are already
  // pointer-like to begin with (for example, C strings and and
  // arrays). This presents wrinkles here, since an array type
  // in LLVM is already effectively a pointer (you can feed it
  // directly into a GEP as opposed to having to take the address of
  // it first).  Bypass the effects of the address operator if
  // this is the case. This is hacky, maybe I can come up with a
  // better solution for this issue(?).
  if (llvm::isa<llvm::ConstantArray>(bexpr->value()))
    return bexpr;
  if (bexpr->value()->getType() == stringType()->type() &&
      bexpr->isConstant())
    return bexpr;

  // If the value we're trying to take the address of is a composite
  // constant, we have to spill it to memory here in order for us to
  // take its address.
  llvm::Value *val = bexpr->value();
  if (bexpr->isConstant()) {
    llvm::Constant *cval = llvm::cast<llvm::Constant>(val);
    Bvariable *cv = genVarForConstant(cval, bexpr->btype());
    val = cv->value();
  }

  // When using non-integral pointers, the Go pointer types (Btype)
  // are in address space 1. Local variables (allocas) are always
  // in address space 0. We need to insert a cast if we are taking
  // the address of a local variable.
  llvm::Type *valtyp = val->getType();
  assert(valtyp->isPointerTy());
  if (valtyp->getPointerAddressSpace() != addressSpace_) {
    llvm::Type *typ =
        llvm::PointerType::get(valtyp->getContext(), addressSpace_);
    val = new llvm::AddrSpaceCastInst(val, typ, "ascast");
  }

  // Create new expression with proper type.
  Btype *pt = pointer_type(bexpr->btype());
  Bexpression *rval = nbuilder_.mkAddress(pt, val, bexpr, location);
  std::string adtag(bexpr->tag());
  adtag += ".ad";
  rval->setTag(adtag);
  const VarContext &vc = bexpr->varContext();
  rval->setVarExprPending(vc.lvalue(), vc.addrLevel() + 1);

  return rval;
}

Bexpression *Llvm_backend::materializeConversion(Bexpression *convExpr)
{
  Location location = convExpr->location();
  Btype *type = convExpr->btype();
  std::vector<Bexpression *> iexprs =
      nbuilder_.extractChildenAndDestroy(convExpr);
  assert(iexprs.size() == 1);
  Bexpression *expr = iexprs[0];

  // For composite-init-pending values, materialize a variable now.
  if (expr->compositeInitPending()) {
    assert(!expr->varExprPending());
    expr = resolveCompositeInit(expr, nullptr);
  }

  llvm::Value *val = expr->value();
  assert(val);
  llvm::Type *valType = val->getType();
  llvm::Type *toType = type->type();

  // In the varexpr pending case, decide what to do depending on whether
  // the var is in an lvalue or rvalue context. For something like
  //
  //     var y int32
  //     z = int64(y)
  //
  // we want to force the load of "y" before converting to int64. For
  // an lvalue context, the conversion will be applied to the pointed-to-type
  // as well as the value type.
  if (expr->varExprPending()) {
    bool lvalue = expr->varContext().lvalue();
    if (!lvalue) {
      expr = resolveVarContext(expr);
      val = expr->value();
      valType = val->getType();
    }
    if (lvalue || useCopyForLoadStore(type->type())) {
      llvm::Type *et = expr->btype()->type();
      if (valType->isPointerTy())
        toType = llvm::PointerType::get(toType->getContext(), addressSpace_);
    }
  }

  // If we're converting between two different Btypes that have the
  // same underlying LLVM type, then we can create a new Bexpression
  // for the conversion but not do anything else.
  if (toType == valType) {
    Bexpression *rval =
        nbuilder_.mkConversion(type, expr->value(), expr, location);
    if (expr->varExprPending())
      rval->setVarExprPending(expr->varContext());
    return rval;
  }

  // If we're applying a conversion to an aggregate constant, call a helper to
  // see if we can create a new (but equivalent) constant value using the target
  // type. If this works, we're effectively done. If the conversion doesn't
  // succeed, materialize a variable containing the constant and apply the
  // conversion to the variable's type (which will be a pointer to the type of
  // the constant), then flag the result as "load pending".
  bool pending = false;
  if (expr->isConstant() && val->getType()->isAggregateType()) {
    llvm::Constant *cval = llvm::cast<llvm::Constant>(val);
    assert(valType == cval->getType());
    llvm::Value *convertedValue = genConvertedConstant(cval, toType);
    if (convertedValue != nullptr) {
      // We have a new value of the correct type. Wrap a conversion
      // expr around it and return.
      return nbuilder_.mkConversion(type, convertedValue, expr, location);
    }
    // materialize constant into variable.
    Bvariable *cv = genVarForConstant(cval, expr->btype());
    val = cv->value();
    valType = val->getType();
    toType = llvm::PointerType::get(toType, addressSpace_);
    pending = true;
  }

  Bexpression *rval = nullptr;

  LIRBuilder builder(context_, llvm::ConstantFolder());

  // Pointer type to pointer-sized-integer type. Comes up when
  // converting function pointer to function descriptor (during
  // creation of function descriptor vals) or constant array to
  // uintptr (as part of GC symbol initializer creation), and in other
  // places in FE-generated code (ex: array index checks).
  if (valType->isPointerTy() && toType == llvmIntegerType()) {
    if (val->getType()->getPointerAddressSpace() != 0) {
      // We are using non-integral pointer. Cast to address space 0
      // before casting to int.
      llvm::Type *pt = llvm::PointerType::get(val->getContext(), 0);
      std::string tname(namegen("ascast"));
      val = builder.CreateAddrSpaceCast(val, pt, tname);
      expr = nbuilder_.mkConversion(type, val, expr, location);
    }
    std::string tname(namegen("pticast"));
    llvm::Value *pticast = builder.CreatePtrToInt(val, toType, tname);
    rval = nbuilder_.mkConversion(type, pticast, expr, location);
  }

  // Pointer-sized-integer type to pointer type. This comes up
  // in type hash/compare functions.
  if (toType->isPointerTy() && valType == llvmIntegerType()) {
    llvm::Type *pt = toType;
    if (toType->getPointerAddressSpace() != 0) {
      // We are using non-integral pointer. Cast to address space 0
      // first.
      pt = llvm::PointerType::get(toType->getContext(), 0);
    }
    std::string tname(namegen("itpcast"));
    llvm::Value *itpcast = builder.CreateIntToPtr(val, pt, tname);
    rval = nbuilder_.mkConversion(type, itpcast, expr, location);
    if (pt != toType) {
      std::string tname(namegen("ascast"));
      llvm::Value *ascast = builder.CreateAddrSpaceCast(itpcast, toType, tname);
      rval = nbuilder_.mkConversion(type, ascast, rval, location);
    }
  }

  // For pointer conversions (ex: *int32 => *int64) create an
  // appropriate bitcast.
  if (valType->isPointerTy() && toType->isPointerTy()) {
    std::string tag(namegen("cast"));
    llvm::Value *bitcast = builder.CreatePointerBitCastOrAddrSpaceCast(val, toType, tag);
    rval = nbuilder_.mkConversion(type, bitcast, expr, location);
  }

  // Integer-to-integer conversions
  // FIXME: the type of the the operand could be AuxT, which we use
  // to wrap an LLVM type for intrinsics. Assume it is signed for now.
  // If this turns to be an issue, we should define the correct Btype
  // for intrinsics.
  if (valType->isIntegerTy() && toType->isIntegerTy()) {
    llvm::IntegerType *valIntTyp =
        llvm::cast<llvm::IntegerType>(valType);
    llvm::IntegerType *toIntTyp =
        llvm::cast<llvm::IntegerType>(toType);
    unsigned valbits = valIntTyp->getBitWidth();
    unsigned tobits = toIntTyp->getBitWidth();
    llvm::Value *conv = nullptr;
    if (tobits > valbits) {
      if (expr->btype()->type() == llvmBoolType() ||
          (expr->btype()->castToBIntegerType() &&
           expr->btype()->castToBIntegerType()->isUnsigned()))
        conv = builder.CreateZExt(val, toType, namegen("zext"));
      else
        conv = builder.CreateSExt(val, toType, namegen("sext"));
    } else {
      conv = builder.CreateTrunc(val, toType, namegen("trunc"));
    }
    rval = nbuilder_.mkConversion(type, conv, expr, location);
  }

  // Float -> float conversions
  if (toType->isFloatingPointTy() && valType->isFloatingPointTy()) {
    llvm::Value *conv = nullptr;
    if (toType == llvmFloatType() && valType == llvmDoubleType())
      conv = builder.CreateFPTrunc(val, toType, namegen("fptrunc"));
    else if (toType == llvmDoubleType() && valType == llvmFloatType())
      conv = builder.CreateFPExt(val, toType, namegen("fpext"));
    else
      assert(0 && "unexpected float type");
    rval =  nbuilder_.mkConversion(type, conv, expr, location);
  }

  // Float -> integer conversions
  if (toType->isIntegerTy() && valType->isFloatingPointTy()) {
    llvm::Value *conv = nullptr;
    if (type->castToBIntegerType()->isUnsigned())
      conv = builder.CreateFPToUI(val, toType, namegen("ftoui"));
    else
      conv = builder.CreateFPToSI(val, toType, namegen("ftosi"));
    rval = nbuilder_.mkConversion(type, conv, expr, location);
  }

  // Integer -> float conversions
  if (toType->isFloatingPointTy() && valType->isIntegerTy()) {
    llvm::Value *conv = nullptr;
    if (expr->btype()->castToBIntegerType() &&
        expr->btype()->castToBIntegerType()->isUnsigned())
      conv = builder.CreateUIToFP(val, toType, namegen("uitof"));
    else
      conv = builder.CreateSIToFP(val, toType, namegen("sitof"));
    rval = nbuilder_.mkConversion(type, conv, expr, location);
  }

  if (!rval)
    // This case not handled.
    assert(false && "this flavor of conversion not handled");

  // Propagate pending var context if we didn't resolve it here.
  // This may happen for composite values.
  if (expr->varExprPending())
    rval->setVarExprPending(expr->varContext());
  else if (pending)
    rval->setVarExprPending(false, 0);

  return rval;
}

llvm::Value *Llvm_backend::makePointerOffsetGEP(Btype *pt, llvm::Value *idxval,
                                                llvm::Value *sptr) {
  LIRBuilder builder(context_, llvm::ConstantFolder());
  llvm::SmallVector<llvm::Value *, 1> elems(1);
  elems[0] = idxval;
  llvm::Type *eltTy = pt->castToBPointerType()->toType()->type();
  llvm::Value *val = builder.CreateGEP(eltTy, sptr, elems, namegen("ptroff"));
  return val;
}

llvm::Value *Llvm_backend::makeArrayIndexGEP(llvm::ArrayType *llat,
                                             llvm::Value *idxval,
                                             llvm::Value *sptr)
{
  LIRBuilder builder(context_, llvm::ConstantFolder());
  llvm::SmallVector<llvm::Value *, 2> elems(2);
  elems[0] = llvm::ConstantInt::get(llvmInt32Type(), 0);
  elems[1] = idxval;
  llvm::Value *val = builder.CreateGEP(llat, sptr, elems, namegen("index"));
  return val;
}

llvm::Value *Llvm_backend::makeFieldGEP(unsigned fieldIndex, llvm::Type *sty,
                                        llvm::Value *sptr) {
  assert(sptr->getType()->isPointerTy());
  llvm::StructType *llst = llvm::cast<llvm::StructType>(sty);
  LIRBuilder builder(context_, llvm::ConstantFolder());
  assert(fieldIndex < llst->getNumElements());
  std::string tag(namegen("field"));

  llvm::Value *val =
      builder.CreateConstInBoundsGEP2_32(llst, sptr, 0, fieldIndex, tag);
  return val;
}

Bexpression *Llvm_backend::materializeStructField(Bexpression *fieldExpr)
{
  Location location = fieldExpr->location();
  const std::string ftag(fieldExpr->tag());
  unsigned index = fieldExpr->fieldIndex();
  std::vector<Bexpression *> fexprs =
      nbuilder_.extractChildenAndDestroy(fieldExpr);
  assert(fexprs.size() == 1);
  Bexpression *bstruct = fexprs[0];

  if (bstruct->compositeInitPending())
    bstruct = resolveCompositeInit(bstruct, nullptr);

  // Construct an appropriate GEP
  llvm::Type *llt = bstruct->btype()->type();
  assert(llt->isStructTy());
  llvm::Value *sval = bstruct->value();
  llvm::Value *fval;
  if (bstruct->isConstant())
    fval = llvm::cast<llvm::Constant>(sval)->getAggregateElement(index);
  else
    fval = makeFieldGEP(index, llt, sval);
  Btype *bft = elementTypeByIndex(bstruct->btype(), index);

  // Wrap result in a Bexpression
  Bexpression *rval = nbuilder_.mkStructField(bft, fval, bstruct,
                                              index, location);

  if (bstruct->varExprPending())
    rval->setVarExprPending(bstruct->varContext());

  std::string tag(bstruct->tag());
  tag += (ftag.empty() ? ".field" : ftag);
  rval->setTag(tag);

  // We're done
  return rval;
}

Bexpression *Llvm_backend::materializeCompound(Bexpression *comExpr)
{
  Location location = comExpr->location();
  std::vector<Bnode *> kids = nbuilder_.extractChildNodesAndDestroy(comExpr);
  assert(kids.size() == 2);
  Bstatement *bstat = kids[0]->castToBstatement();
  assert(bstat);
  Bexpression *bexpr = kids[1]->castToBexpression();
  assert(bexpr);

  bexpr = materialize(bexpr);

  // Compound expressions can be used to produce lvalues, so we don't
  // want to call resolve() on bexpr here.
  // But we do want to resolve composite init.
  if (bexpr->compositeInitPending())
    bexpr = resolveCompositeInit(bexpr, nullptr);

  Bexpression *rval = nbuilder_.mkCompound(bstat, bexpr, bexpr->value(),
                                           location);
  if (bexpr->varExprPending())
    rval->setVarExprPending(bexpr->varContext());
  return rval;
}

Bexpression *Llvm_backend::materializeConditional(Bexpression *condExpr)
{
  Bfunction *function = condExpr->getFunction();
  Location location = condExpr->location();
  Btype *btype = condExpr->btype();
  std::vector<Bexpression *> cexprs =
      nbuilder_.extractChildenAndDestroy(condExpr);
  assert(cexprs.size() == 2 || cexprs.size() == 3);
  Bexpression *condition = cexprs[0];
  Bexpression *then_expr = cexprs[1];
  Bexpression *else_expr = (cexprs.size() == 3 ? cexprs[2] : nullptr);

  condition = resolveVarContext(condition);
  then_expr = resolve(then_expr);
  if (else_expr)
    else_expr = resolve(else_expr);

  std::vector<Bvariable *> novars;
  Bblock *thenBlock = nbuilder_.mkBlock(function, novars, location);
  Bblock *elseBlock = nullptr;
  Bvariable *tempv = nullptr;

  // FIXME: add lifetime intrinsics for temp var below.
  Bstatement *thenStmt = nullptr;
  if (!btype || then_expr->btype() == void_type() || btype == void_type())
    thenStmt = expression_statement(function, then_expr);
  else
    tempv = temporary_variable(function, nullptr,
                               btype, then_expr, false,
                               location, &thenStmt);
  nbuilder_.addStatementToBlock(thenBlock, thenStmt);

  if (else_expr) {
    Bstatement *elseStmt = nullptr;
    elseBlock = nbuilder_.mkBlock(function, novars, location);
    if (!btype || btype == void_type() || else_expr->btype() == void_type()) {
      elseStmt = expression_statement(function, else_expr);
    } else {
      // Capture "else_expr" into temporary. Type needs to agree with
      // then_expr if then_expr had non-void type.
      if (!tempv) {
        tempv = temporary_variable(function, nullptr,
                                   btype, else_expr, false,
                                   location, &elseStmt);
      } else {
        // Ideally it would be nice to assert that the types are
        // identical for if_expr and else_expr, but particularly for
        // pointer types we need to allow for some disagreement (ex:
        // nil_pointer_expression, which is untyped/polymorphic).
        // Assume that the type checking in the call to
        // assignment_statement will catch any problems.
        Bexpression *varExpr = var_expression(tempv, location);
        elseStmt = assignment_statement(function, varExpr, else_expr, location);
      }
    }
    nbuilder_.addStatementToBlock(elseBlock, elseStmt);
  }

  // Wrap up and return the result
  Bstatement *ifStmt = if_statement(function, condition,
                                    thenBlock, elseBlock, location);

  Bexpression *rval = (tempv ?
                       var_expression(tempv, location) :
                       nbuilder_.mkVoidValue(void_type()));
  Bexpression *result =
      materialize(compound_expression(ifStmt, rval, location));
  return result;
}

Bexpression *Llvm_backend::materializeUnary(Bexpression *unExpr)
{
  Operator op = unExpr->op();
  Location location = unExpr->location();
  std::vector<Bexpression *> uexprs =
      nbuilder_.extractChildenAndDestroy(unExpr);
  assert(uexprs.size() == 1);
  Bexpression *expr = uexprs[0];

  expr = resolveVarContext(expr);
  Btype *bt = expr->btype();

  switch (op) {
    case OPERATOR_MINUS: {
      assert(false && "should have been expanded away");
      break;
    }

    case OPERATOR_NOT: {
      LIRBuilder builder(context_, llvm::ConstantFolder());
      assert(isBooleanType(bt));

      // FIXME: is this additional compare-to-zero needed? Or can we be certain
      // that the value in question has a single bit set?
      Bexpression *bzero = zero_expression(bt);
      llvm::Value *cmp =
          builder.CreateICmpNE(expr->value(), bzero->value(), namegen("icmp"));
      Btype *lbt = makeAuxType(llvmBoolType());
      Bexpression *cmpex =
          nbuilder_.mkBinaryOp(OPERATOR_EQEQ, lbt, cmp, bzero, expr, location);
      llvm::Constant *one = llvm::ConstantInt::get(llvmBoolType(), 1);
      llvm::Value *xorex = builder.CreateXor(cmp, one, namegen("xor"));
      Bexpression *notex = nbuilder_.mkUnaryOp(op, lbt, xorex, cmpex, location);
      Bexpression *tobool = lateConvert(bool_type(), notex, location);
      return tobool;
    }
    case OPERATOR_XOR: {
      // ^x    bitwise complement    is m ^ x  with m = "all bits set to 1"
      //                             for unsigned x and  m = -1 for signed x
      assert(bt->type()->isIntegerTy());
      LIRBuilder builder(context_, llvm::ConstantFolder());
      llvm::Value *onesval = llvm::Constant::getAllOnesValue(bt->type());
      llvm::Value *xorExpr = builder.CreateXor(expr->value(), onesval,
                                               namegen("xor"));
      Bexpression *rval = nbuilder_.mkUnaryOp(op, bt, xorExpr, expr, location);
      return rval;
      break;
    }
    default:
      assert(false && "unexpected unary opcode");
  }
  return nullptr;
}

static llvm::CmpInst::Predicate compare_op_to_pred(Operator op,
                                                   llvm::Type *typ,
                                                   bool isUnsigned)
{
  bool isFloat = typ->isFloatingPointTy();

  if (isFloat) {
    switch (op) {
    case OPERATOR_EQEQ:
      return llvm::CmpInst::Predicate::FCMP_OEQ;
    case OPERATOR_NOTEQ:
      return llvm::CmpInst::Predicate::FCMP_UNE;
    case OPERATOR_LT:
      return llvm::CmpInst::Predicate::FCMP_OLT;
    case OPERATOR_LE:
      return llvm::CmpInst::Predicate::FCMP_OLE;
    case OPERATOR_GT:
      return llvm::CmpInst::Predicate::FCMP_OGT;
    case OPERATOR_GE:
      return llvm::CmpInst::Predicate::FCMP_OGE;
    default:
      break;
    }
  } else {
    switch (op) {
    case OPERATOR_EQEQ:
      return llvm::CmpInst::Predicate::ICMP_EQ;
    case OPERATOR_NOTEQ:
      return llvm::CmpInst::Predicate::ICMP_NE;
    case OPERATOR_LT:
      return (isUnsigned ? llvm::CmpInst::Predicate::ICMP_ULT
                         : llvm::CmpInst::Predicate::ICMP_SLT);
    case OPERATOR_LE:
      return (isUnsigned ? llvm::CmpInst::Predicate::ICMP_ULE
                         : llvm::CmpInst::Predicate::ICMP_SLE);
    case OPERATOR_GT:
      return (isUnsigned ? llvm::CmpInst::Predicate::ICMP_UGT
                         : llvm::CmpInst::Predicate::ICMP_SGT);
    case OPERATOR_GE:
      return (isUnsigned ? llvm::CmpInst::Predicate::ICMP_UGE
                         : llvm::CmpInst::Predicate::ICMP_SGE);
    default:
      break;
    }
  }
  assert(false);
  return llvm::CmpInst::BAD_ICMP_PREDICATE;
}

std::pair<llvm::Value *, llvm::Value *>
Llvm_backend::convertForBinary(Operator op,
                               Bexpression *left,
                               Bexpression *right)
{
  llvm::Value *leftVal = left->value();
  llvm::Value *rightVal = right->value();
  std::pair<llvm::Value *, llvm::Value *> rval =
      std::make_pair(leftVal, rightVal);

  llvm::Type *leftType = leftVal->getType();
  llvm::Type *rightType = rightVal->getType();
  if (leftType == rightType)
    return rval;

  // Case 1: nil op X
  if (llvm::isa<llvm::ConstantPointerNull>(leftVal) &&
      rightType->isPointerTy()) {
    BexprLIRBuilder builder(context_, left);
    std::string tag(namegen("cast"));
    llvm::Value *bitcast = builder.CreateBitCast(leftVal, rightType, tag);
    rval.first = bitcast;
    return rval;
  }

  // Case 2: X op nil
  if (llvm::isa<llvm::ConstantPointerNull>(rightVal) &&
      leftType->isPointerTy()) {
    BexprLIRBuilder builder(context_, right);
    std::string tag(namegen("cast"));
    llvm::Value *bitcast = builder.CreateBitCast(rightVal, leftType, tag);
    rval.second = bitcast;
    return rval;
  }

  // Case 3: shift with different sized operands (ex: int64(v) << uint8(3)).
  // Promote or demote shift amount operand to match width of left operand.
  if ((op == OPERATOR_LSHIFT || op == OPERATOR_RSHIFT) &&
      leftType != rightType) {
    BexprLIRBuilder builder(context_, right);
    llvm::IntegerType *leftITyp = llvm::cast<llvm::IntegerType>(leftType);
    llvm::IntegerType *rightITyp = llvm::cast<llvm::IntegerType>(rightType);
    llvm::Value *conv = nullptr;
    if (leftITyp->getBitWidth() > rightITyp->getBitWidth())
      conv = builder.CreateZExt(rightVal, leftType, namegen("zext"));
    else
      conv = builder.CreateTrunc(rightVal, leftType, namegen("trunc"));
    rval.second = conv;
    return rval;
  }

  // Case 4: pointer type comparison
  // We check that if both are pointer types and pointing to the same type,
  // insert a cast (it doesn't matter we cast which one). This mostly needed
  // for circular pointer types (ex: type T *T; var p, q T; p == &q), where
  // the two sides have semantically identical types but with different
  // representations (in this case, T vs. *T).
  if (leftType->isPointerTy() && rightType->isPointerTy()) {
    BPointerType *lbpt = left->btype()->castToBPointerType();
    BPointerType *rbpt = right->btype()->castToBPointerType();
    if (lbpt->toType()->type() == rbpt->toType()->type()) {
      BexprLIRBuilder builder(context_, right);
      std::string tag(namegen("cast"));
      llvm::Value *bitcast = builder.CreateBitCast(rightVal, leftType, tag);
      rval.second = bitcast;
      return rval;
    }
  }

  return rval;
}

Bexpression *Llvm_backend::materializeBinary(Bexpression *binExpr)
{
  Operator op = binExpr->op();
  Location location = binExpr->location();
  std::vector<Bexpression *> bexprs =
      nbuilder_.extractChildenAndDestroy(binExpr);
  assert(bexprs.size() == 2);
  Bexpression *left = bexprs[0];
  Bexpression *right = bexprs[1];

  Btype *bltype = left->btype();
  Btype *brtype = right->btype();

  left = resolveVarContext(left);
  right = resolveVarContext(right);
  assert(left->value() && right->value());

  std::pair<llvm::Value *, llvm::Value *> converted =
      convertForBinary(op, left, right);
  llvm::Value *leftVal = converted.first;
  llvm::Value *rightVal = converted.second;
  llvm::Type *ltype = leftVal->getType();
  llvm::Type *rtype = rightVal->getType();
  assert(ltype == rtype);
  BIntegerType *blitype = bltype->castToBIntegerType();
  BIntegerType *britype = brtype->castToBIntegerType();
  assert((blitype == nullptr) == (britype == nullptr));
  bool isUnsigned = false;
  if (blitype) {
    // As of Go 1.13, shift amount is allowed to be a signed integer.
    // Note that the front end emits tests to guard against negative
    // shift amounts.
    assert(op == OPERATOR_LSHIFT || op == OPERATOR_RSHIFT ||
           blitype->isUnsigned() == britype->isUnsigned());
    isUnsigned = blitype->isUnsigned();
  }
  LIRBuilder builder(context_, llvm::ConstantFolder());
  llvm::Value *val = nullptr;

  switch (op) {
  case OPERATOR_EQEQ:
  case OPERATOR_NOTEQ:
  case OPERATOR_LT:
  case OPERATOR_LE:
  case OPERATOR_GT:
  case OPERATOR_GE: {
    llvm::CmpInst::Predicate pred = compare_op_to_pred(op, ltype, isUnsigned);
    if (ltype->isFloatingPointTy())
      val = builder.CreateFCmp(pred, leftVal, rightVal, namegen("fcmp"));
    else
      val = builder.CreateICmp(pred, leftVal, rightVal, namegen("icmp"));
    Btype *bcmpt = makeAuxType(llvmBoolType());
    // gen compare...
    Bexpression *cmpex =
        nbuilder_.mkBinaryOp(op, bcmpt, val, left, right, location);
    // ... widen to go boolean type
    return lateConvert(bool_type(), cmpex, location);
  }
  case OPERATOR_MINUS: {
    if (ltype->isFloatingPointTy())
      val = builder.CreateFSub(leftVal, rightVal, namegen("fsub"));
    else
      val = builder.CreateSub(leftVal, rightVal, namegen("sub"));
    break;
  }
  case OPERATOR_PLUS: {
    if (ltype->isFloatingPointTy())
      val = builder.CreateFAdd(leftVal, rightVal, namegen("fadd"));
    else
      val = builder.CreateAdd(leftVal, rightVal, namegen("add"));
    break;
  }
  case OPERATOR_MULT: {
    if (ltype->isFloatingPointTy())
      val = builder.CreateFMul(leftVal, rightVal, namegen("fmul"));
    else
      val = builder.CreateMul(leftVal, rightVal, namegen("mul"));
    break;
  }
  case OPERATOR_MOD: {
    assert(! ltype->isFloatingPointTy());
    if (isUnsigned)
      val = builder.CreateURem(leftVal, rightVal, namegen("mod"));
    else
      val = builder.CreateSRem(leftVal, rightVal, namegen("mod"));
    break;
  }
  case OPERATOR_DIV: {
    if (ltype->isFloatingPointTy())
      val = builder.CreateFDiv(leftVal, rightVal, namegen("fdiv"));
    else if (isUnsigned)
      val = builder.CreateUDiv(leftVal, rightVal, namegen("div"));
    else
      val = builder.CreateSDiv(leftVal, rightVal, namegen("div"));
    break;
  }
  case OPERATOR_OROR:
    // Note that the FE will have already expanded out || in a control
    // flow context (short circuiting)

    // fall through...

  case OPERATOR_OR: {
    assert(!ltype->isFloatingPointTy());
    val = builder.CreateOr(leftVal, rightVal, namegen("ior"));
    break;
  }
  case OPERATOR_BITCLEAR:
    // Note that the FE already inserted a complement op to RHS. So
    // this is effectively an AND expression.
    // fall through...
  case OPERATOR_ANDAND:
    // Note that the FE will have already expanded out && in a control
    // flow context (short circuiting).

    // fall through...

  case OPERATOR_AND: {
    assert(!ltype->isFloatingPointTy());
    val = builder.CreateAnd(leftVal, rightVal, namegen("iand"));
    break;
  }
  case OPERATOR_XOR: {
    assert(!ltype->isFloatingPointTy() && !rtype->isFloatingPointTy());
    val = builder.CreateXor(leftVal, rightVal, namegen("xor"));
    break;
  }
  case OPERATOR_LSHIFT: {
    // Note that the FE already inserted conditionals for checking
    // large shift amounts. So this can simply lower to a shift
    // instruction.
    assert(!ltype->isFloatingPointTy() && !rtype->isFloatingPointTy());
    val = builder.CreateShl(leftVal, rightVal, namegen("shl"));
    break;
  }
  case OPERATOR_RSHIFT: {
    // Note that the FE already inserted conditionals for checking
    // large shift amounts. So this can simply lower to a shift
    // instruction.
    assert(!ltype->isFloatingPointTy() && !rtype->isFloatingPointTy());
    if (isUnsigned)
      val = builder.CreateLShr(leftVal, rightVal, namegen("shr"));
    else
      val = builder.CreateAShr(leftVal, rightVal, namegen("shr"));
    break;
  }
  default:
    std::cerr << "Op " << op << " unhandled\n";
    assert(false);
  }

  return nbuilder_.mkBinaryOp(op, bltype, val, left, right, location);
}

Bexpression *Llvm_backend::materializeComposite(Bexpression *comExpr)
{
  Location location = comExpr->location();
  Btype *btype = comExpr->btype();
  const std::vector<unsigned long> *indexes = nbuilder_.getIndices(comExpr);
  std::vector<Bexpression *> vals =
      nbuilder_.extractChildenAndDestroy(comExpr);

  llvm::Type *llt = btype->type();
  unsigned numElements = 0;
  assert(llt->isStructTy() || llt->isArrayTy());
  llvm::Type *llct = nullptr;
  if (llt->isStructTy()) {
    llvm::StructType *llst = llvm::cast<llvm::StructType>(llt);
    numElements = llst->getNumElements();
    assert(vals.size() == numElements);
    llct = llst;
  } else {
    llvm::ArrayType *llat = llvm::cast<llvm::ArrayType>(llt);
    numElements = llat->getNumElements();
    llct = llat;
  }

  // Constant values?
  bool isConstant = valuesAreConstant(vals);
  if (isConstant)
    return makeConstCompositeExpr(btype, llct, numElements,
                                  indexes, vals, location);
  else
    return makeDelayedCompositeExpr(btype, llct, numElements,
                                    indexes, vals, location);
}

Bexpression *
Llvm_backend::makeDelayedCompositeExpr(Btype *btype,
                                       llvm::Type *llct,
                                       unsigned numElements,
                                       const std::vector<unsigned long> *indexes,
                                       const std::vector<Bexpression *> &vals,
                                       Location location)
{
  std::vector<Bexpression *> init_vals(numElements);
  if (indexes) {
    unsigned long nvals = vals.size();
    unsigned long nindxs = indexes->size();
    std::set<unsigned long> touched;
    for (unsigned ii = 0; ii < nindxs; ++ii) {
      auto idx = (*indexes)[ii];
      if (numElements != nvals)
        touched.insert(idx);
      init_vals[idx] = vals[ii];
    }
    if (numElements != nvals) {
      for (unsigned long ii = 0; ii < numElements; ++ii) {
        Btype *bElemTyp = elementTypeByIndex(btype, ii);
        if (touched.find(ii) == touched.end())
          init_vals[ii] = zero_expression(bElemTyp);
      }
    }
  } else {
    init_vals = vals;
  }

  // Here the NULL value signals that we want to delay full instantiation
  // of this constant expression until we can identify the storage for it.
  llvm::Value *nilval = nullptr;
  Binstructions noInstructions;
  Bexpression *ccon = nbuilder_.mkComposite(btype, nilval, init_vals,
                                            noInstructions, location);
  return ccon;
}

Bexpression *
Llvm_backend::makeConstCompositeExpr(Btype *btype,
                                     llvm::Type *llct,
                                     unsigned numElements,
                                     const std::vector<unsigned long> *indexes,
                                     const std::vector<Bexpression *> &vals,
                                     Location location)
{
  llvm::Value *scon;

  // If all elements are zero, just create a zero value for the
  // aggregate type. No need to create LLVM Value for each element.
  bool allZero = true;
  for (auto v : vals) {
    llvm::Constant *con = llvm::cast<llvm::Constant>(v->value());
    if (!con->isNullValue()) {
      allZero = false;
      break;
    }
  }
  if (allZero)
    scon = llvm::ConstantAggregateZero::get(llct);
  else {
    llvm::SmallVector<llvm::Constant *, 64> llvals(numElements);
    unsigned long nvals = vals.size();

    if (indexes) {
      std::set<unsigned long> touched;
      unsigned long nindxs = indexes->size();
      for (unsigned ii = 0; ii < nindxs; ++ii) {
        auto idx = (*indexes)[ii];
        if (numElements != nvals)
          touched.insert(idx);
        Bexpression *bex = vals[ii];
        llvm::Constant *con = llvm::cast<llvm::Constant>(bex->value());
        llvm::Type *elt = TypeManager::getLlvmTypeAtIndex(llct, ii);
        if (elt != con->getType()) {
          con = genConvertedConstant(con, elt);
          assert(con != nullptr);
        }
        llvals[idx] = con;
      }
      if (numElements != nvals) {
        for (unsigned long ii = 0; ii < numElements; ++ii) {
          if (touched.find(ii) == touched.end()) {
            llvm::Type *elt = TypeManager::getLlvmTypeAtIndex(llct, ii);
            llvals[ii] = llvm::Constant::getNullValue(elt);
          }
        }
      }
    } else {
      for (unsigned long ii = 0; ii < numElements; ++ii) {
        llvm::Constant *con = llvm::cast<llvm::Constant>(vals[ii]->value());
        llvm::Type *elt = TypeManager::getLlvmTypeAtIndex(llct, ii);
        if (elt != con->getType()) {
          con = genConvertedConstant(con, elt);
          assert(con != nullptr);
        }
        llvals[ii] = con;
      }
    }

    if (llct->isStructTy()) {
      llvm::StructType *llst = llvm::cast<llvm::StructType>(llct);
      scon = llvm::ConstantStruct::get(llst, llvals);
    } else {
      llvm::ArrayType *llat = llvm::cast<llvm::ArrayType>(llct);
      scon = llvm::ConstantArray::get(llat, llvals);
    }
  }

  Binstructions noInstructions;
  Bexpression *bcon = nbuilder_.mkComposite(btype, scon, vals,
                                            noInstructions, location);
  return makeGlobalExpression(bcon, scon, btype, location);
}

Bexpression *Llvm_backend::materializePointerOffset(Bexpression *ptroffExpr)
{
  Location location = ptroffExpr->location();
  std::vector<Bexpression *> cexprs =
      nbuilder_.extractChildenAndDestroy(ptroffExpr);
  assert(cexprs.size() == 2);
  Bexpression *base = cexprs[0];
  Bexpression *index = cexprs[1];

  // Resolve index expression
  index = resolveVarContext(index);

  // When a pointer offset expression appears in a left-hand-side (assignment)
  // context, the expected semantics are that location to be written is the
  // one pointer to by the result of the pointer offset, meaning that we want
  // to propagate any "lvalue-ness" found in 'base' up into the result
  // expression (as opposed to delaying a load from 'base' itself).
  //
  // To achieve this effect, the code below essentially hides away the
  // lvalue context on 'base' and then re-establishes it on 'rval' after the
  // GEP. This is a painful hack, it would be nice to have a clean way
  // to do this.
  VarContext vc;
  bool setLHS = false;
  if (base->varExprPending() && base->varContext().lvalue()) {
    setLHS = true;
    base->resetVarExprContext();
    base->setVarExprPending(false, 0);
  }
  base = resolveVarContext(base);

  // Construct an appropriate GEP
  llvm::Value *gep =
      makePointerOffsetGEP(base->btype(), index->value(), base->value());

  // Wrap in a Bexpression
  Bexpression *rval = nbuilder_.mkPointerOffset(base->btype(), gep, base,
                                                index, location);

  // Re-establish lvalue context (as described above)
  if (setLHS)
    rval->setVarExprPending(true, 1);

  std::string tag(base->tag());
  tag += ".ptroff";
  rval->setTag(tag);

  // We're done
  return rval;
}

Bexpression *Llvm_backend::materializeArrayIndex(Bexpression *arindExpr)
{
  Location location = arindExpr->location();
  std::vector<Bexpression *> cexprs =
      nbuilder_.extractChildenAndDestroy(arindExpr);
  assert(cexprs.size() == 2);
  Bexpression *barray = cexprs[0];
  Bexpression *index = cexprs[1];

  if (barray->compositeInitPending())
    barray = resolveCompositeInit(barray, nullptr);

  index = resolveVarContext(index);

  // Construct an appropriate GEP
  llvm::ArrayType *llat =
      llvm::cast<llvm::ArrayType>(barray->btype()->type());
  llvm::Value *aval = barray->value();
  llvm::Value *ival = index->value();
  llvm::Value *eval = nullptr;
  bool pending = false;
  if (barray->isConstant()) {
    if (index->isConstant())
      eval = llvm::cast<llvm::Constant>(aval)->getAggregateElement(llvm::cast<llvm::Constant>(ival));
    else {
      // Constant array with non-constant index. Put the array
      // into a temp var and load from there.
      llvm::Constant *cval = llvm::cast<llvm::Constant>(aval);
      Bvariable *cv = genVarForConstant(cval, barray->btype());
      aval = cv->value();
      pending = true;
    }
  }
  if (!eval)
    eval = makeArrayIndexGEP(llat, ival, aval);

  Btype *bet = elementTypeByIndex(barray->btype(), 0);

  // Wrap in a Bexpression
  Bexpression *rval = nbuilder_.mkArrayIndex(bet, eval, barray, index, location);
  if (pending)
    rval->setVarExprPending(false, 0);
  if (barray->varExprPending())
    rval->setVarExprPending(barray->varContext());

  std::string tag(barray->tag());
  tag += ".index";
  rval->setTag(tag);

  // We're done
  return rval;
}

struct GenCallState {
  CABIOracle oracle;
  BlockLIRBuilder builder;
  std::vector<Bexpression *> resolvedArgs;
  llvm::SmallVector<llvm::Value *, 16> llargs;
  llvm::Value *chainVal;
  llvm::Value *sretTemp;
  BFunctionType *calleeFcnType;
  Bfunction *callerFcn;

  GenCallState(llvm::LLVMContext &context,
               Bfunction *callerFunc,
               BFunctionType *calleeFcnTyp,
               TypeManager *tm,
               NameGen *namegen,
               llvm::Function *dummyFcn)
      : oracle(calleeFcnTyp, tm),
        builder(dummyFcn, namegen),
        chainVal(nullptr),
        sretTemp(nullptr),
        calleeFcnType(calleeFcnTyp),
        callerFcn(callerFunc) { }
};

static bool needSretTemp(const CABIParamInfo &returnInfo,
                         BFunctionType *calleeFcnTyp)
{
  if (returnInfo.disp() == ParmIgnore)
    return false;
  if (returnInfo.disp() == ParmIndirect)
    return true;
  if (returnInfo.abiType()->isAggregateType())
    return true;
  if (calleeFcnTyp->resultType()->type()->isAggregateType())
    return true;
  return false;
}

void Llvm_backend::genCallProlog(GenCallState &state)
{
  const CABIParamInfo &returnInfo = state.oracle.returnInfo();
  if (needSretTemp(returnInfo, state.calleeFcnType)) {
    assert(state.sretTemp == nullptr);
    std::string tname(namegen("sret.actual"));
    Btype *resTyp = state.calleeFcnType->resultType();
    assert(state.callerFcn);
    state.sretTemp = state.callerFcn->createTemporary(resTyp, tname);
    if (returnInfo.disp() == ParmIndirect)
      state.llargs.push_back(state.sretTemp);
  }

  // Chain param if needed
  const CABIParamInfo &chainInfo = state.oracle.chainInfo();
  if (chainInfo.disp() != ParmIgnore) {
    assert(chainInfo.disp() == ParmDirect);
    llvm::Value *cval = state.chainVal;
    if (cval == nullptr)
      cval = llvm::UndefValue::get(llvmPtrType());
    state.llargs.push_back(cval);
  }
}

void
Llvm_backend::genCallMarshallArgs(const std::vector<Bexpression *> &fn_args,
                                  GenCallState &state)
{
  for (unsigned idx = 0; idx < fn_args.size(); ++idx) {
    const CABIParamInfo &paramInfo = state.oracle.paramInfo(idx);

    if (paramInfo.attr() == AttrNest)
      continue;

    BlockLIRBuilder &builder = state.builder;

    // For arguments not passed by value, no call to resolveVarContext
    // (we want var address, not var value).
    if (paramInfo.disp() == ParmIndirect) {
      Bexpression *fnarg = fn_args[idx];
      if (fnarg->compositeInitPending())
        fnarg = resolveCompositeInit(fnarg, nullptr);
      state.resolvedArgs.push_back(fnarg);
      llvm::Value *val = fnarg->value();
      assert(val);
      // spill a constant arg to memory if needed
      if (fnarg->isConstant()) {
        llvm::Constant *cval = llvm::cast<llvm::Constant>(val);
        Bvariable *cv = genVarForConstant(cval, fn_args[idx]->btype());
        val = cv->value();
      }
      llvm::Type *vt = val->getType();
      assert(vt->isPointerTy());
      if (paramInfo.attr() == AttrByVal && vt->getPointerAddressSpace() != 0) {
        // We pass a stack address, which is always in address space 0.
        std::string castname(namegen("ascast"));
        llvm::Type *pt = llvm::PointerType::get(vt->getContext(), 0);
        val = builder.CreateAddrSpaceCast(val, pt, castname);
      }

      // For some architectures, such as arm64, the indirect parameter needs to
      // be copied to the space allocated by the caller on the stack, and pass
      // the address of the copied version to the callee.
      if (paramInfo.attr() == AttrDoCopy) {
        TypeManager *tm = state.oracle.tm();
        Btype *bty = fnarg->btype();
        uint64_t sz = tm->typeSize(bty);
        uint64_t algn = tm->typeAlignment(bty);
        llvm::MaybeAlign malgn(algn);
        std::string tname(namegen("doCopy.addr"));
        llvm::Value *tmpV = state.callerFcn->createTemporary(bty, tname);
        builder.CreateMemCpy(tmpV, malgn, val, malgn, sz);
        val = tmpV;
      }
      state.llargs.push_back(val);
      continue;
    }

    // Resolve argument
    Varexpr_context ctx = varContextDisp(fn_args[idx]);
    if (paramInfo.abiTypes().size() == 2)
      ctx = VE_lvalue;
    Bexpression *resarg = resolve(fn_args[idx], ctx);
    state.resolvedArgs.push_back(resarg);

    if (paramInfo.disp() == ParmIgnore)
      continue;

    // At this point we're passing an argument directly,
    // as opposed to in memory.
    assert(paramInfo.disp() == ParmDirect);

    llvm::Value *val = resarg->value();

    if (paramInfo.abiTypes().size() == 1) {
      if (ctx == VE_lvalue) {
        // Passing single-eightbyte struct or array directly.
        if (resarg->isConstant()) {
          // If the value we're passing is a composite constant, we have to
          // spill it to memory here in order for the casts below to work.
          llvm::Constant *cval = llvm::cast<llvm::Constant>(val);
          Bvariable *cv = genVarForConstant(cval, resarg->btype());
          val = cv->value();
        }
        std::string castname(namegen("cast"));
        // We are going to do a load, so the address space does not matter.
        // It seems we may get here with either address space, so we just
        // do an address-space-preserving cast.
        llvm::Type *ptv =
            llvm::PointerType::get(paramInfo.abiType(),
                                   val->getType()->getPointerAddressSpace());
        llvm::Value *bitcast = builder.CreateBitCast(val, ptv, castname);
        std::string ltag(namegen("ld"));
        llvm::Value *ld = builder.CreateLoad(paramInfo.abiType(), bitcast, ltag);
        state.llargs.push_back(ld);
        continue;
      }
      // Passing a single 8-byte-or-less argument.

      // Apply any necessary sign-extensions or zero-extensions.
      if (paramInfo.abiType()->isIntegerTy()) {
        if (paramInfo.attr() == AttrZext)
          val = builder.CreateZExt(val, paramInfo.abiType(), namegen("zext"));
        else if (paramInfo.attr() == AttrSext)
          val = builder.CreateZExt(val, paramInfo.abiType(), namegen("sext"));
      }
      state.llargs.push_back(val);
      continue;
    }

    // This now corresponds to the case of passing the contents of
    // a small structure via no more than CABIParamInfo::ABI_TYPES_MAX_SIZE
    // pieces / params.
    assert(paramInfo.abiTypes().size() <= CABIParamInfo::ABI_TYPES_MAX_SIZE);
    assert(paramInfo.attr() == AttrNone);
    assert(ctx == VE_lvalue);

    // Create a struct type of the appropriate shape
    llvm::Type *llst = paramInfo.computeABIStructType(typeManager());
    llvm::Type *ptst = makeLLVMPointerType(llst);

    // If the value we're passing is a composite constant, we have to
    // spill it to memory here in order for the casts below to work.
    // Note that the spill is not needed if the value corresponds to a
    // delated load of a composite variable (in which case it will
    // already be an address). For example, if resarg corresponds to
    // an anonymous constant value like [2]float64{10.0,10.0} then we
    // need to spill, whereas if we're dealing with a reference to a
    // named global constant, there is no need to spill.
    if (resarg->isConstant() && val->getType() == resarg->btype()->type()) {
      llvm::Constant *cval = llvm::cast<llvm::Constant>(val);
      Bvariable *cv = genVarForConstant(cval, resarg->btype());
      val = cv->value();
    }

    // Cast the value to the struct type
    std::string tag(namegen("cast"));
    llvm::Value *bitcast =
        builder.CreatePointerBitCastOrAddrSpaceCast(val, ptst, tag);

    // Load up each field
    for ( unsigned i = 0; i < paramInfo.abiTypes().size(); ++i) {
      std::string ftag(namegen("field"+std::to_string(i)));
      llvm::Value *fieldgep =
          builder.CreateConstInBoundsGEP2_32(llst, bitcast, 0, i, ftag);
      std::string ltag(namegen("ld"));
      llvm::Value *ld = builder.CreateLoad(paramInfo.abiTypes()[i], fieldgep, ltag);
      state.llargs.push_back(ld);
    }
  }
}

void Llvm_backend::genCallAttributes(GenCallState &state, llvm::CallInst *call)
{
  const llvm::AttributeList &callAttrList = call->getAttributes();
  llvm::AttrBuilder retAttrs(context_, callAttrList.getRetAttrs());
  const std::vector<Btype *> &paramTypes = state.calleeFcnType->paramTypes();
  size_t na = state.oracle.getFunctionTypeForABI()->getNumParams();
  llvm::SmallVector<llvm::AttributeSet, 4> argAttrs(na);

  // Sret attribute if needed
  const CABIParamInfo &returnInfo = state.oracle.returnInfo();
  if (returnInfo.disp() == ParmIndirect) {
    llvm::AttrBuilder ab(context_);
    ab.addStructRetAttr(state.calleeFcnType->resultType()->type());
    ab.addAttribute(llvm::Attribute::get(call->getContext(), "go_sret"));
    argAttrs[0] = llvm::AttributeSet::get(context_, ab);
  }

  // Nest attribute if needed
  const CABIParamInfo &chainInfo = state.oracle.chainInfo();
  if (chainInfo.disp() != ParmIgnore) {
    llvm::AttrBuilder ab(context_);
    ab.addAttribute(llvm::Attribute::Nest);
    argAttrs[chainInfo.sigOffset()] =
        llvm::AttributeSet::get(context_, ab);
  }

  // Remainder of param attributes
  for (unsigned idx = 0; idx < paramTypes.size(); ++idx) {
    const CABIParamInfo &paramInfo = state.oracle.paramInfo(idx);
    if (paramInfo.disp() == ParmIgnore)
      continue;
    assert(paramInfo.attr() != AttrNest);
    assert(paramInfo.attr() != AttrStructReturn);
    if (paramInfo.attr() != AttrNone) {
      unsigned off = paramInfo.sigOffset();
      llvm::AttrBuilder ab(context_);
      if (paramInfo.attr() == AttrByVal) {
        ab.addByValAttr(paramTypes[idx]->type());
      } else if (paramInfo.attr() == AttrZext) {
        ab.addAttribute(llvm::Attribute::ZExt);
      } else if (paramInfo.attr() == AttrSext) {
        ab.addAttribute(llvm::Attribute::SExt);
      }
      argAttrs[off] = llvm::AttributeSet::get(context_, ab);
    }
  }

  call->setAttributes(
      llvm::AttributeList::get(context_,
                               callAttrList.getFnAttrs(),
                               llvm::AttributeSet::get(context_, retAttrs),
                               argAttrs));
}

void Llvm_backend::genCallEpilog(GenCallState &state,
                                 llvm::Instruction *callInst,
                                 Bexpression *callExpr)
{
  const CABIParamInfo &returnInfo = state.oracle.returnInfo();

  if (needSretTemp(returnInfo, state.calleeFcnType)) {
    assert(state.sretTemp);
    assert(callExpr->value() == state.sretTemp);
    callExpr->setVarExprPending(VE_rvalue, 0);

    if (returnInfo.disp() == ParmDirect) {
      // The call is returning something by value that doesn't match
      // the expected abstract result type of the function. Cast the
      // sret storage location to a pointer to the abi type and store
      // the ABI return value into it.
      llvm::Type *rt = (returnInfo.abiTypes().size() == 1 ?
                        returnInfo.abiType()  :
                        returnInfo.computeABIStructType(typeManager()));
      llvm::Type *ptrt = llvm::PointerType::get(rt, 0);
      std::string castname(namegen("cast"));
      llvm::Value *bitcast =
          state.builder.CreateBitCast(state.sretTemp,
                                      ptrt, castname);
      std::string stname(namegen("st"));
      state.builder.CreateStore(callInst, bitcast);
      callExpr->appendInstructions(state.builder.instructions());
    }
  }
}

// makeGetgArm64 uses inline asm to implement the function of
// runtime.getg used in Go files on linux arm64.
static llvm::Value *makeGetgArm64(Btype *resType,
                                  BlockLIRBuilder *builder,
                                  Llvm_backend *be)
{
  std::string asmStr;
  std::string constr;
  if (be->module().getPICLevel() > llvm::PICLevel::Level::NotPIC ||
      be->module().getPIELevel() > llvm::PIELevel::Level::Default ) {
    // Dynamic link.
    asmStr += "adrp x0, :tlsdesc:runtime.g\n";
    asmStr += "ldr  $0, [x0, :tlsdesc_lo12:runtime.g]\n";
    asmStr += "add  x0, x0, :tlsdesc_lo12:runtime.g\n";
    asmStr += ".tlsdesccall runtime.g\n";
    asmStr += "blr  $0\n";
    asmStr += "mrs  $0, TPIDR_EL0\n";
    asmStr += "ldr  $0, [$0, x0]\n";
    // We need to clobber x0 because we have to use it to pass parameters.
    // We also only need to clobber x0, because the TLS descriptor helper
    // function only modifies x0
    constr += "=r,~{x0}";
    llvm::FunctionType *fnType =
        llvm::FunctionType::get(resType->type(), llvm::ArrayRef<llvm::Type*>{}, false);
    llvm::Value *callee = llvm::InlineAsm::get(fnType, llvm::StringRef(asmStr),
                                               llvm::StringRef(constr), true);
    std::string callname(be->namegen("asmcall"));
    return builder->CreateCall(fnType, callee, {}, callname);
  } else {
    // Static link.
    asmStr += "adrp $0, :gottprel:runtime.g\n";
    asmStr += "ldr  $0, [$0, #:gottprel_lo12:runtime.g]\n";
    asmStr += "mrs  $1, tpidr_el0\n";
    asmStr += "ldr  $0, [$1, $0]\n";
    // In order not to clobber registers, we declare a temporary variable
    // as the second output and return the first output.
    constr += "=r,=r";
    llvm::Type *tempRegType = llvm::IntegerType::get(builder->getContext(), 64);
    llvm::Type *fnResType = llvm::StructType::create(
        builder->getContext(), {resType->type(), tempRegType});
    llvm::FunctionType *fnType =
        llvm::FunctionType::get(fnResType, llvm::ArrayRef<llvm::Type*>{}, false);
    llvm::Value *callee = llvm::InlineAsm::get(fnType, llvm::StringRef(asmStr),
                                               llvm::StringRef(constr), true);
    std::string callname(be->namegen("asmcall"));
    llvm::Instruction *calI = builder->CreateCall(fnType, callee, {}, callname);
    return builder->CreateExtractValue(calI, {0});
  }
}

// Inline runtime.getg, generate a load of g.
// This is not done as a builtin because, unlike other builtins,
// we need the FE to tell us the result type.
static llvm::Value *makeGetg(Btype *resType,
                             BlockLIRBuilder *builder,
                             Llvm_backend *be)
{
  llvm::GlobalValue* g = be->module().getGlobalVariable("runtime.g");
  if (!g) {
    unsigned int flags = Backend::variable_is_external;
    Location location; // dummy
    Bvariable* bv = be->global_variable("runtime.g", "runtime.g", resType,
                                        flags, location);
    g = llvm::cast<llvm::GlobalValue>(bv->value());
    g->setThreadLocal(true);
  }
  if (be->triple().getArch() == llvm::Triple::aarch64)
    return makeGetgArm64(resType, builder, be);
  else
    return builder->CreateLoad(resType->type(), g);
}

Bexpression *Llvm_backend::materializeCall(Bexpression *callExpr)
{
  Location location = callExpr->location();
  Bfunction *caller = callExpr->getFunction();
  std::vector<Bexpression *> cexprs =
      nbuilder_.extractChildenAndDestroy(callExpr);
  Bexpression *fn_expr = cexprs[0];
  Bexpression *chain_expr = cexprs[1];
  std::vector<Bexpression *> fn_args;
  for (unsigned idx = 2; idx < cexprs.size(); ++idx) {
    fn_args.push_back(cexprs[idx]);
  }

  // Resolve fcn. Expect pointer-to-function type here.
  fn_expr = resolveVarContext(fn_expr);
  assert(fn_expr->btype()->type()->isPointerTy());
  BFunctionType *calleeFcnTyp = unpackFunctionType(fn_expr->btype());
  Btype *rbtype = calleeFcnTyp->resultType();
  llvm::Value *fnval = fn_expr->value();

  // Some intrinsic functions need additional args. Add them.
  // TODO: currently this is specific to llvm.cttz, llvm.memmove, and
  // llvm.memcpy; if the list expands too much more it might make
  // sense to incorporate a description of the extra args into the
  // builtin table entry.
  if (llvm::isa<llvm::Function>(fnval)) {
    llvm::Function *fcn = llvm::cast<llvm::Function>(fnval);
    switch (fcn->getIntrinsicID()) {
      case llvm::Intrinsic::cttz:
      case llvm::Intrinsic::ctlz: {
        // @llvm.cttz.i32  (i32 <src>, i1 <is_zero_undef>)
        // Add the <is_zero_undef> arg.
        // GCC's __builtin_ctz results undefined for 0 input.
        llvm::Value *con = llvm::ConstantInt::getTrue(context_);
        Btype *bt = makeAuxType(llvmBoolType());
        Bexpression *conexpr = nbuilder_.mkConst(bt, con);
        fn_args.push_back(conexpr);
        break;
      }
      case llvm::Intrinsic::memmove:
      case llvm::Intrinsic::memcpy: {
        // memmove/memcpy take additional volatile arg
        // volatile => false
        llvm::Value *fcon = llvm::ConstantInt::getFalse(context_);
        Btype *bt = makeAuxType(llvmBoolType());
        Bexpression *volexpr = nbuilder_.mkConst(bt, fcon);
        fn_args.push_back(volexpr);
        break;
      }
      case llvm::Intrinsic::prefetch: {
        // prefetch takes an additional arg for cache type
        // (0: instruction, 1: data).
        Btype *buint32t = integerType(true, 32);
        llvm::Constant *c1 = llvm::ConstantInt::get(llvmInt32Type(), 1);
        Bexpression *conexpr = nbuilder_.mkConst(buint32t, c1);
        fn_args.push_back(conexpr);
        break;
      }
      case llvm::Intrinsic::eh_dwarf_cfa: {
        // llvm.eh.dwarf.cfa takes an additional arg 0.
        Btype *buint32t = integerType(true, 32);
        llvm::Constant *c1 = llvm::ConstantInt::get(llvmInt32Type(), 0);
        Bexpression *conexpr = nbuilder_.mkConst(buint32t, c1);
        fn_args.push_back(conexpr);
        break;
      }
      default: {
        // at the moment no other instrinsics need special handling
      }
    }
  }

  // State object to help with marshalling of call arguments, etc.
  llvm::Function *dummyFcn = errorFunction_->function();
  GenCallState state(context_, caller, calleeFcnTyp, typeManager(),
                     nameTags(), dummyFcn);

  // Static chain expression if applicable
  if (chain_expr->btype() != void_type()) {
    chain_expr = resolveVarContext(chain_expr);
    assert(chain_expr->btype()->type()->isPointerTy());
    Btype *bpt = makeAuxType(llvmPtrType());
    chain_expr = lateConvert(bpt, chain_expr, location);
    assert(chain_expr->value() != nullptr);
    state.chainVal = chain_expr->value();
  }

  // Set up for call (including creation of return tmp if needed)
  genCallProlog(state);

  // Unpack / resolve / marshall arguments
  genCallMarshallArgs(fn_args, state);

  // Create the actual call instruction
  llvm::CallInst *call = nullptr;
  llvm::Value *callValue = nullptr;
  if (llvm::isa<llvm::Function>(fnval)) {
    llvm::Function *fcn = llvm::cast<llvm::Function>(fnval);
    BuiltinEntry *be = builtinTable_->lookup(fcn->getName().str());
    if (be) {
      BuiltinExprMaker makerfn = be->exprMaker();
      if (makerfn)
        callValue = makerfn(state.llargs, &state.builder, this);
    } else if (fcn->getName() == "runtime.getg" && !DisableInlineGetg)
      callValue = makeGetg(rbtype, &state.builder, this);
  }
  if (!callValue) {
    llvm::FunctionType *llft =
        llvm::cast<llvm::FunctionType>(calleeFcnTyp->type());
    bool isvoid = llft->getReturnType()->isVoidTy();
    std::string callname(isvoid ? "" : namegen("call"));
    call = state.builder.CreateCall(llft, fnval,
                                    state.llargs, callname);
    genCallAttributes(state, call);
    callValue = (state.sretTemp ? state.sretTemp : call);
  }

  Binstructions callInstructions;
  std::vector<llvm::Instruction *> binstructions = state.builder.instructions();
  for (auto i : binstructions)
    callInstructions.appendInstruction(i);

  Bexpression *rval =
      nbuilder_.mkCall(rbtype, callValue, caller, fn_expr, chain_expr,
                       state.resolvedArgs, callInstructions, location);

  if (call)
    genCallEpilog(state, call, rval);

  return rval;
}

// Walk the specified expression and invoke setVarExprPending on
// each var expression, with correct lvalue/rvalue tag depending on
// context.

class VarContextVisitor {
 public:
  VarContextVisitor(Bexpression *top,
                    Varexpr_context lvalueContext,
                    bool dumpDiffs)
      : dumpDiffs_(dumpDiffs)
  {
    if (lvalueContext == VE_lvalue && isMem(top))
      setLvalue(top);
  }

  std::pair< std::pair<VisitDisp, VisitChildDisp>, Bnode *>
  visitChildPre(Bnode *parent, Bnode *child) {

    Bexpression *eparent = parent->castToBexpression();
    assert(eparent != nullptr);

    // Don't descend into stmts or non-var nodes with values.
    Bexpression *echild = child->castToBexpression();
    if (child->isStmt() || (echild->value() != nullptr &&
                            echild->flavor() != N_Var))
      return std::make_pair(std::make_pair(ContinueWalk, SkipChild), child);

    // Propagate lvalue property down from parent to child through a memory
    // operation such as a fieldref or arrayindex if applicable. For example,
    // for the tree build from go code "x.f1[y]" such as
    //
    //             array_index
    //             /      \.
    //        field      var(y)
    //        /
    //      var(x)
    //
    // If the top node (array_index) is in a left-hand-side position,
    // then we want to flag "field" and "var(x)" nodes as being in an
    // LHS context also, but not the "var(y)" node (it is not being
    // assigned).
    assert(echild != nullptr);
    if (isLvalue(eparent) && isMem(echild)) {
      Bexpression *cmem = memArg(eparent);
      if (cmem == echild)
        setLvalue(echild);
    }
    return std::make_pair(std::make_pair(ContinueWalk, VisitChild), child);
  }

  // Apply "var pending" tags to var exprs bottom up, once downward propagation
  // of lvalue context is complete.
  std::pair<VisitDisp, Bnode *> visitNodePost(Bnode *node)
  {
    Bexpression *expr = node->castToBexpression();
    if (expr == nullptr || (expr->value() && expr->flavor() != N_Var))
      return std::make_pair(ContinueWalk, expr);

    if (expr->flavor() == N_Var)
      setVarExprPending(expr, isLvalue(expr), 0);

    // Debugging only. This is intended to provide a way to compare the
    // tags applied by the frontend vs the tags this visitor generates.
    if (dumpDiffs_)
      dumpDiff(expr);

    auto it = varcontext_.find(expr);
    if (it != varcontext_.end()) {
      VarContext vc(it->second);
      bool lvalue = vc.lvalue();
      if (expr->varExprPending()) {
        assert(vc.equal(expr->varContext()));
      } else {
        expr->setVarExprPending(lvalue, 0);
      }
    }

    return std::make_pair(ContinueWalk, expr);
  }

  // boilerplate
  std::pair<VisitDisp, Bnode *> visitNodePre(Bnode *node) {
    return std::make_pair(ContinueWalk, node);
  }

  // boilerplate
  std::pair<VisitDisp, Bnode *> visitChildPost(Bnode *parent, Bnode *child) {
      return std::make_pair(ContinueWalk, child);
  }

 private:

  // Debugging only.
  void dumpDiff(Bexpression *expr)
  {
    if (expr->value() && expr->flavor() != N_Var)
      return;

    VarContext oldvc;
    if (expr->varExprPending())
      oldvc = expr->varContext();

    VarContext newvc;
    auto nit = varcontext_.find(expr);
    if (nit != varcontext_.end())
      newvc = nit->second;

    if (newvc.equal(oldvc))
      return;

    std::cerr << "Expr " << expr->id()
              << " " << expr->flavstr() << " ";
    if (oldvc.pending()) {
      std::cerr << "old VC(" << (oldvc.pending() ? "true" : "false")
                << "," << (oldvc.lvalue() ? "lval" : "rval")
                << "," << oldvc.addrLevel() << ") ";
    }
    if (newvc.pending()) {
      std::cerr << "new VC(" << (newvc.pending() ? "true" : "false")
                << "," << (newvc.lvalue() ? "lval" : "rval")
                << "," << newvc.addrLevel() << ") ";
    }
    std::cerr << "\n";
    expr->dump();
    std::cerr << "\n";
  }

  Bexpression *memArg(Bexpression *expr) {
    const std::vector<Bnode *> &kids = expr->children();
    switch(expr->flavor()) {
      case N_StructField:
      case N_ArrayIndex:
      case N_Address:
      case N_Conversion:
      case N_PointerOffset:
        return kids[0]->castToBexpression();
      default:
        return nullptr;
    }
  }

  bool isMem(Bexpression *expr) {
    switch(expr->flavor()) {
      case N_Var:
      case N_StructField:
      case N_Address:
      case N_Deref:
      case N_Conversion:
      case N_ArrayIndex:
      case N_PointerOffset:
        return true;
      default:
        return false;
    }
  }

  void setLvalue(Bexpression *expr) {
    assert(lvalue_.find(expr) == lvalue_.end());
    lvalue_.insert(expr);
  }

  bool isLvalue(Bexpression *expr) {
    return lvalue_.find(expr) != lvalue_.end();
  }

  void setVarExprPending(Bexpression *expr, bool lvalue, unsigned addrLevel) {
    assert(expr);
    VarContext vc(lvalue, addrLevel);
    varcontext_[expr] = vc;
  }

 private:
  std::set<Bnode *> lvalue_;
  std::map<Bexpression *, VarContext> varcontext_;
  bool dumpDiffs_;
};

// Helper visitor class for expression folding; removes redundant
// nodes in preparation for materialization.

class FoldVisitor {
 public:
  FoldVisitor(Llvm_backend *be) : be_(be) { }

  std::pair<VisitDisp, Bnode *> visitNodePost(Bnode *node) {
    Bexpression *expr = node->castToBexpression();
    if (!expr)
      return std::make_pair(ContinueWalk, node);
    if (expr && expr->value())
      return std::make_pair(ContinueWalk, node);

    // Fold addr(deref(X)) and deref(addr(X)) => X
    if (node->flavor() == N_Address) {
      std::vector<Bexpression *> akids = expr->getChildExprs();
      if (akids[0]->flavor() == N_Deref) {
        Bexpression *deref = akids[0];

        // Extract children and delete first the addr node, then the
        // deref node. Order is important; if we delete the deref first
        // then the integrity visitor will wind up trying to access the
        // deleted deref.
        be_->nodeBuilder().extractChildenAndDestroy(expr);
        std::vector<Bexpression *> dkids =
            be_->nodeBuilder().extractChildenAndDestroy(deref);

        // Return result
        expr = dkids[0];
      }
    } else if (node->flavor() == N_Deref) {
      std::vector<Bexpression *> dkids = expr->getChildExprs();
      if (dkids[0]->flavor() == N_Address) {
        Bexpression *address = dkids[0];

        // Extract children and delete first the deref node, then the
        // addr node. Order is important; if we delete the addr first
        // then the integrity visitor will wind up trying to access the
        // deleted addr.
        be_->nodeBuilder().extractChildenAndDestroy(expr);
        std::vector<Bexpression *> akids =
            be_->nodeBuilder().extractChildenAndDestroy(address);

        // Return result
        expr = akids[0];
      }
    }
    return std::make_pair(ContinueWalk, expr);
  }

  // If child is a statement (ex: compound expr) or if child
  // already has an LLVM value, then prune walk at this node.
  std::pair< std::pair<VisitDisp, VisitChildDisp>, Bnode *>
  visitChildPre(Bnode *parent, Bnode *child) {
    Bexpression *echild = child->castToBexpression();
    if (child->isStmt() || echild->value() != nullptr)
      return std::make_pair(std::make_pair(ContinueWalk, SkipChild), child);
    return std::make_pair(std::make_pair(ContinueWalk, VisitChild), child);
  }

  // Boilerplate
  std::pair<VisitDisp, Bnode *> visitNodePre(Bnode *node) {
    return std::make_pair(ContinueWalk, node);
  }
  std::pair<VisitDisp, Bnode *> visitChildPost(Bnode *parent, Bnode *child) {
    return std::make_pair(ContinueWalk, child);
  }

 private:
  Llvm_backend *be_;
};

class MaterializeVisitor {
 public:
  MaterializeVisitor(Llvm_backend *be,
                     Bexpression *topNode,
                     Varexpr_context ctx)
      : be_(be), topNode_(topNode), ctx_(ctx) { }

  std::pair<VisitDisp, Bnode *> visitNodePre(Bnode *node) {
    return std::make_pair(ContinueWalk, node);
  }
  std::pair<VisitDisp, Bnode *> visitNodePost(Bnode *node) {
    Bexpression *expr = node->castToBexpression();
    if (expr && expr->value())
      return std::make_pair(ContinueWalk, node);
    switch(node->flavor()) {
      case N_EmptyStmt:
      case N_LabelStmt:
      case N_GotoStmt:
      case N_ExprStmt:
      case N_ReturnStmt:
      case N_DeferStmt:
      case N_IfStmt:
      case N_ExcepStmt:
      case N_BlockStmt:
      case N_SwitchStmt: {
        return std::make_pair(ContinueWalk, node);
      }
      case N_Error:
      case N_Const:
      case N_Var:
      case N_FcnAddress:
      case N_LabelAddress: {
        break;
      }
      case N_Conversion: {
        expr = be_->materializeConversion(expr);
        break;
      }
      case N_Deref: {
        bool isLHS = (expr == topNode_ && ctx_ == VE_lvalue);
        expr = be_->materializeIndirect(expr, isLHS);
        break;
      }
      case N_Address: {
        expr = be_->materializeAddress(expr);
        break;
      }
      case N_UnaryOp: {
        expr = be_->materializeUnary(expr);
        break;
      }
      case N_StructField: {
        expr = be_->materializeStructField(expr);
        break;
      }
      case N_BinaryOp: {
        expr = be_->materializeBinary(expr);
        break;
      }
      case N_Compound: {
        expr = be_->materializeCompound(expr);
        break;
      }
      case N_ArrayIndex: {
        expr = be_->materializeArrayIndex(expr);
        break;
      }
      case N_PointerOffset: {
        expr = be_->materializePointerOffset(expr);
        break;
      }
      case N_Composite: {
        expr = be_->materializeComposite(expr);
        break;
      }
      case N_Call: {
        expr = be_->materializeCall(expr);
        break;
      }
      case N_Conditional: {
        expr = be_->materializeConditional(expr);
        break;
      }
    }
    assert(expr->value() != nullptr ||
           expr->flavor() == N_Composite ||
           expr->btype() == be_->void_type());
    return std::make_pair(ContinueWalk, expr);
  }

  // If child is a statement (ex: compound expr), then no need to
  // visit subtree (should already be materialized). Similarly if
  // child already has an LLVM value, then prune walk at this node
  std::pair< std::pair<VisitDisp, VisitChildDisp>, Bnode *>
  visitChildPre(Bnode *parent, Bnode *child) {
    Bexpression *echild = child->castToBexpression();
    if (child->isStmt() || echild->value() != nullptr)
      return std::make_pair(std::make_pair(ContinueWalk, SkipChild), child);
    return std::make_pair(std::make_pair(ContinueWalk, VisitChild), child);
  }

  std::pair<VisitDisp, Bnode *> visitChildPost(Bnode *parent, Bnode *child) {
    return std::make_pair(ContinueWalk, child);
  }
 private:
  Llvm_backend *be_;
  Bexpression *topNode_;
  Varexpr_context ctx_;
};

Bexpression *Llvm_backend::materialize(Bexpression *expr,
                                       Varexpr_context lvalueContext)

{
  // Repair any node sharing at this point-- the materializer
  // assumes that any node it visits can be destroyed/replaced
  // without impacting some other portion of the tree.
  enforceTreeIntegrity(expr);

  // TODO:
  // - don't really need a treewalk in the non-LHS case to apply
  //   can context tags; it would be simpler to only do the walk
  //   in the LHS case (and just apply var context tags when
  //   var expression is initially created)
  // - an extension of the above: pass in the LHS/RHS context
  //   and propagate recursively during the materialize() walk,
  //   instead of having a separate tree-walk here.

  // Locate and tag var expressions within the tree, selecting LHS or
  // RHS context as appropriate. Needs to be done after the call above
  // so as to insure that there are no share var expressions.
  VarContextVisitor vcvis(expr, lvalueContext, false);
  update_walk_nodes(expr, vcvis);

  // Perform some basic folding operations. This is easier to do
  // here so as not to worry about sharing.
  FoldVisitor fvis(this);
  Bnode *folded = update_walk_nodes(expr, fvis);
  expr = folded->castToBexpression();

  // Walk to materialize llvm values.
  MaterializeVisitor mvis(this, expr, lvalueContext);
  Bnode *materialized = update_walk_nodes(expr, mvis);
  return materialized->castToBexpression();
}

Bexpression *Llvm_backend::lateConvert(Btype *type,
                                       Bexpression *expr,
                                       Location loc)
{
  return materialize(convert_expression(type, expr, loc));
}
