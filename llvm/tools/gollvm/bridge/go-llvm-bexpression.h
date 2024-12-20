//===-- go-llvm-bexpression.h - decls for gofrontend 'Bexpression' class --===//
//
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
//
// Defines Bexpression and related classes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVMGOFRONTEND_GO_LLVM_BEXPRESSION_H
#define LLVMGOFRONTEND_GO_LLVM_BEXPRESSION_H

// Currently these need to be included before backend.h
#include "go-llvm-linemap.h"
#include "go-location.h"
#include "go-llvm-btype.h"
#include "go-llvm-bnode.h"

#include "backend.h"

namespace llvm {
class Instruction;
class Value;
class raw_ostream;
}

class Bstatement;
class BnodeBuilder;

// Mixin class for a list of instructions

class Binstructions {
public:
  Binstructions() {}
  explicit Binstructions(const std::vector<llvm::Instruction *> &instructions)
      : instructions_(instructions) {}

  const std::vector<llvm::Instruction *> &instructions() const {
    return instructions_;
  }
  void appendInstruction(llvm::Instruction *inst) {
    assert(isValidInst(inst));
    instructions_.push_back(inst);
  }
  void appendInstructions(const std::vector<llvm::Instruction *> &ilist) {
    for (auto inst : ilist) {
      assert(isValidInst(inst));
      instructions_.push_back(inst);
    }
  }

  void clear() { instructions_.clear(); }

  // Locate 'inst' within the instructions vector, then remove 'inst' and all
  // subsequent instructions from the list and return them as a vector. Will
  // assert if 'inst' is not found in the list.
  std::vector<llvm::Instruction *> extractInstsAfter(llvm::Instruction *inst);

private:
  std::vector<llvm::Instruction *> instructions_;

  // Certain classes of instructions should not be hanging off a
  // Bexpression -- they should only appear in a function prolog.
  bool isValidInst(llvm::Instruction *);
};

// Helper class used as part of class Bexpression. This object records
// whether a Bexpression subtree contains a root variable expression,
// and if so, whether that variable expression appears in an "lvalue"
// (left-hand-side of assignment) or "rvalue" (right hand side of
// assignment) context, as whether a address operator has been applied
// to the variable.  Once we reach a point where we have concrete
// consumer for the subtree of (var/address/indrect/field/indexing)
// ops, we can then use this information to decide whether to
// materialize an address or perform a load. See the main Bexpression
// comment for more info here.

class VarContext {
 public:
  VarContext() : addrLevel_(0), lvalue_(false), pending_(false) { }
  VarContext(bool lvalue, unsigned addrLevel)
      : addrLevel_(addrLevel), lvalue_(lvalue), pending_(true) { }

  bool pending() const { return pending_; }
  unsigned addrLevel() const { return addrLevel_; }
  bool lvalue() const { return lvalue_; }
  void setPending(bool lvalue, unsigned addrLevel) {
    assert(!pending_);
    pending_ = true;
    lvalue_ = lvalue;
    addrLevel_ = addrLevel;
  }
  void reset() { assert(pending_); pending_ = false; }
  bool equal(const VarContext &other) const {
    return (pending_ == other.pending_ &&
            addrLevel_ == other.addrLevel_ &&
            lvalue_ == other.lvalue_);
  }

 private:
  unsigned addrLevel_;
  bool lvalue_;
  bool pending_;
};

// Whether a variable expression appears in lvalue (assignment) context.
enum Varexpr_context {
  VE_rvalue,
  VE_lvalue
};

// Bexpression is the backend representation of an expression, meaning
// that it produces a value (llvm::Value) and will encapsulate some
// set of instructions (llvm::Instruction) needed to produce that
// value.  The overall strategy for Bexpressions is to produce LLVM
// values in an "eager" fashion, that is, any LLVM instructions needed
// to compute the expression's value are computed as soon as possible
// (typically right at the point where the Bexpression is
// constructed).  For example, if Llvm_backend::binary_operator is
// invoked to create a Bexpression for an addition operation, it will
// eagerly manufacture a new llvm::BinaryOperator object and return a
// new Bexpression that encapsulates that object.
//
// This eager strategy works well for the most part, but has to be
// relaxed in some instances, notably variable references and
// composite initializers. Consider the following Go code:
//
//    func foo(qq int64) int64 {
//      var ad [4]int64 = [4]int64{ 0, 1, qq, 3 }
//
// Frontend will invoke the Backend::array_constructor_expression()
// method for the initializer ("{ 0, 1, qq, 3 }"). Because this
// initializer is not a pure constant (it contains a reference to the
// variable "qq"), the LLVM instructions we generate for it will have
// to store the array values to a chunk of memory. At the point where
// array_constructor_expression() is called, we don't yet know what
// expression or statement the value will feed into, meaning that it
// would be premature to emit LLVM instructions to initialize that
// storage.
//
// To address this, non-constant composite expressions use a lazy
// value generation strategy; the Bexpression itself is marked as
// delayed (no LLVM value), and then once we reach the point where we
// know what the storage will be, someone makes a call to
// BnodeBuilder::finishComposite to generate the necessary store
// instructions and finalize the LLVM value.
//
// Second area where we want to delay things is in handling of
// variable expressions. For example, consider the following Go code:
//
//        struct X { a, b int64 }
//        func foo(q, r int64, ip *int64, px *X) int64 {
//           r = q
//           r = **&ip
//           ip = &q
//         px.a = px.b
//
// The right hand side expression trees for these statements would look like:
//
//        stmt 1:   varexpr("q")
//        stmt 2:   deref(deref(address(varexpr("ip")))).
//        stmt 3:   address(varexpr("q"))
//        stmt 4:   field(deref(varexpr("px"),'b')
//
// At the point where Llvm_backend::var_expression is called, we don't
// know the context for the consuming instruction. For statement 1, we
// want to generate a load for the varexpr, however in statement 3 it
// would be premature to create the load (since the varexpr is feeding
// into an address operator). This is handled using the VarContext
// helper object (define above).

class Bexpression : public Bnode, public Binstructions {
 public:
  // no public constructor, use BnodeBuilder instead
  virtual ~Bexpression();

  llvm::Value *value() const { return value_; }
  Btype *btype() const { return btype_; }
  const std::string &tag() const { return tag_; }
  void setTag(const std::string &tag) { tag_ = tag; }

  bool varExprPending() const;
  const VarContext &varContext() const;
  void setVarExprPending(bool lvalue, unsigned addrLevel);
  void setVarExprPending(const VarContext &vc);
  void resetVarExprContext();
  bool compositeInitPending() const;
  const std::vector<Bexpression *> getChildExprs() const;

  // Return context disposition based on expression type.
  // Composite values need to be referred to by address,
  // whereas non-composite values can be used directly.
  Varexpr_context varContextDisp() const;

  // Return whether the expression is a constant.
  // True implies the underlying llvm::Value is llvm::Constant.
  bool isConstant();

  // debugging
  void dumpInstructions(llvm::raw_ostream &os, unsigned ilevel,
                        Llvm_linemap *linemap, bool terse) const;

  // dump with source line info
  void srcDump(Llvm_linemap *);

  friend class BnodeBuilder;

 private:
  Bexpression(NodeFlavor fl, const std::vector<Bnode *> &kids,
              llvm::Value *val, Btype *typ, Location loc);
  Bexpression(const Bexpression &src);
  void setValue(llvm::Value *val);

  llvm::Value *value_;
  Btype *btype_;
  std::string tag_;
  VarContext varContext_;
};

#endif // LLVMGOFRONTEND_GO_LLVM_BEXPRESSION_H
