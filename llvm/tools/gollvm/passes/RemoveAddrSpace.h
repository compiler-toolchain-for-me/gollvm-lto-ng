//===--- RemoveAddrSpace.h ------------------------------------------------===//
//
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
//
// LLVM backend pass to remove addrspacecast instructions
// in static initializers (because codegen cannot handle
// them).
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_GOLLVM_PASSES_REMOVEADDRSPACE_H
#define LLVM_GOLLVM_PASSES_REMOVEADDRSPACE_H

#include "llvm/IR/DataLayout.h"
#include "llvm/IR/PassManager.h"

namespace llvm {

class RemoveAddrSpacePass : public PassInfoMixin<RemoveAddrSpacePass> {
  DataLayout DL; // data layout without non-integral pointer

public:
  /// Construct a pass with update data layout optional optmizations.
  RemoveAddrSpacePass(const DataLayout &DL) : DL(DL) {}

  /// Run the pass over the module.
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif // LLVM_GOLLVM_PASSES_REMOVEADDRSPACE_H
