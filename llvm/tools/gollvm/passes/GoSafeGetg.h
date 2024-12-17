//===--- GoSafeGetg.h -----------------------------------------------------===//
//
// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
//
// Make sure the TLS address is not cached across a thread switch.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_GOLLVM_PASSES_GOSAFEGETG_H
#define LLVM_GOLLVM_PASSES_GOSAFEGETG_H

#include "llvm/IR/PassManager.h"

namespace llvm {

struct GoSafeGetgPass : public PassInfoMixin<GoSafeGetgPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

} // namespace llvm

#endif // LLVM_GOLLVM_PASSES_GOSAFEGETG_H
