//===--- GollvmOptions.cpp - Gollvm Driver Options Table ------------------===//
//
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//

#include "GollvmOptions.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Option/OptTable.h"
#include "llvm/Option/Option.h"

using namespace llvm::opt;

namespace gollvm {
namespace options {

#define PREFIX(NAME, VALUE) static const char *const NAME[] = VALUE;
#include "GollvmOptions.inc"
#undef PREFIX

#define OPTTABLE_STR_TABLE_CODE
#include "GollvmOptions.inc"
#undef OPTTABLE_STR_TABLE_CODE

#define OPTTABLE_VALUES_CODE
#include "GollvmOptions.inc"
#undef OPTTABLE_VALUES_CODE

#define OPTTABLE_PREFIXES_TABLE_CODE
#include "GollvmOptions.inc"
#undef OPTTABLE_PREFIXES_TABLE_CODE

#define OPTTABLE_PREFIXES_UNION_CODE
#include "GollvmOptions.inc"
#undef OPTTABLE_PREFIXES_UNION_CODE

static const OptTable::Info InfoTable[] = {
#define OPTION(...) LLVM_CONSTRUCT_OPT_INFO(__VA_ARGS__),
#include "GollvmOptions.inc"
#undef OPTION
};

namespace {
class DriverOptTable : public PrecomputedOptTable {
public:
  DriverOptTable()
      : PrecomputedOptTable(OptionStrTable, OptionPrefixesTable, InfoTable,
                            OptionPrefixesUnion) {}
};
}

std::unique_ptr<OptTable> createGollvmDriverOptTable() {
  auto Result = std::make_unique<DriverOptTable>();
  return std::move(Result);
}

}
}
