//===- llvm/tools/gollvm/unittests/BackendCore/BackendArrayStruct.cpp ---===//
//
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//

#include "TestUtils.h"
#include "go-llvm-backend.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "gtest/gtest.h"

//using namespace llvm;
using namespace goBackendUnitTests;

namespace {

class BackendArrayStructTests
    : public testing::TestWithParam<gollvm::driver::CallingConvId> {};

INSTANTIATE_TEST_SUITE_P(
    UnitTest, BackendArrayStructTests,
    goBackendUnitTests::cconvs(),
    [](const testing::TestParamInfo<BackendArrayStructTests::ParamType> &info) {
      std::string name = goBackendUnitTests::ccName(info.param);
      return name;
    });

TEST_P(BackendArrayStructTests, TestStructFieldExprs) {
  auto cc = GetParam();
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();

  //
  // type X struct {
  //    f1 *bool
  //    f2 int32
  // }
  // var loc1 X
  //
  Location loc;
  Btype *bt = be->bool_type();
  Btype *pbt = be->pointer_type(bt);
  Btype *bi32t = be->integer_type(false, 32);
  Btype *s2t = mkBackendStruct(be, pbt, "f1", bi32t, "f2", nullptr);
  Bvariable *loc1 = h.mkLocal("loc1", s2t);

  // var loc2 *X = &loc1
  Btype *ps2t = be->pointer_type(s2t);
  Bexpression *bl1vex = be->var_expression(loc1, loc);
  Bexpression *adl1 = be->address_expression(bl1vex, loc);
  Bvariable *loc2 = h.mkLocal("loc2", ps2t, adl1);

  // var x int32
  // x = loc1.f2
  Bvariable *x = h.mkLocal("x", bi32t);
  Bexpression *vex = be->var_expression(x, loc);
  Bexpression *sex = be->var_expression(loc1, loc);
  Bexpression *fex = be->struct_field_expression(sex, 1, loc);
  h.mkAssign(vex, fex);

  // var b2 bool
  // loc1.f1 = &b2
  Bvariable *b2 = h.mkLocal("b2", bt);
  Bexpression *lvex = be->var_expression(loc1, loc);
  Bexpression *bfex = be->struct_field_expression(lvex, 0, loc);
  Bexpression *b2ex = be->var_expression(b2, loc);
  Bexpression *adb2 = be->address_expression(b2ex, loc);
  h.mkAssign(bfex, adb2);

  // loc2.f2 = 2 (equivalent to (*loc2).f2 = 2)
  Bexpression *lvexi = be->var_expression(loc2, loc);
  bool knValid = false;
  Bexpression *lindx = be->indirect_expression(s2t, lvexi, knValid, loc);
  Bexpression *bfex2 = be->struct_field_expression(lindx, 1, loc);
  Bexpression *bc2 = mkInt32Const(be, 2);
  h.mkAssign(bfex2, bc2);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %loc1, ptr align 8 @const.0, i64 16, i1 false)
    store ptr %loc1, ptr %loc2, align 8
    store i32 0, ptr %x, align 4
    %field.0 = getelementptr inbounds { ptr, i32 }, ptr %loc1, i32 0, i32 1
    %loc1.field.ld.0 = load i32, ptr %field.0, align 4
    store i32 %loc1.field.ld.0, ptr %x, align 4
    store i8 0, ptr %b2, align 1
    %field.1 = getelementptr inbounds { ptr, i32 }, ptr %loc1, i32 0, i32 0
    store ptr %b2, ptr %field.1, align 8
    %loc2.ld.0 = load ptr, ptr %loc2, align 8
    %field.2 = getelementptr inbounds { ptr, i32 }, ptr %loc2.ld.0, i32 0, i32 1
    store i32 2, ptr %field.2, align 4
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, TestStructFieldExprs2) {
  auto cc = GetParam();
  // Testing struct field expression for composites.
  FcnTestHarness h(cc);
  Llvm_backend *be = h.be();
  BFunctionType *befty = mkFuncTyp(be, L_END);
  Bfunction *func = h.mkFunction("foo", befty);

  // type X struct {
  //    f1 *bool
  //    f2 int32
  // }
  Location loc;
  Btype *bt = be->bool_type();
  Btype *pbt = be->pointer_type(bt);
  Btype *bi32t = be->integer_type(false, 32);
  Btype *s2t = mkBackendStruct(be, pbt, "f1", bi32t, "f2", nullptr);

  // Taking a field of non-constant composite.
  // var x, y int32
  // x = X{nil, y}.f2
  Bvariable *x = h.mkLocal("x", bi32t);
  Bvariable *y = h.mkLocal("y", bi32t);
  std::vector<Bexpression *> vals1;
  vals1.push_back(be->zero_expression(pbt));
  vals1.push_back(be->var_expression(y, loc));
  Bexpression *vex1 = be->var_expression(x, loc);
  Bexpression *sex1 = be->constructor_expression(s2t, vals1, loc);
  Bexpression *fex1 = be->struct_field_expression(sex1, 1, loc);
  h.mkAssign(vex1, fex1);

  // Taking a field of constant composite.
  // var z int32
  // z = X{nil, 42}.f2
  Bvariable *z = h.mkLocal("z", bi32t);
  std::vector<Bexpression *> vals2;
  vals2.push_back(be->zero_expression(pbt));
  vals2.push_back(mkInt32Const(be, int32_t(42)));
  Bexpression *vex2 = be->var_expression(z, loc);
  Bexpression *sex2 = be->constructor_expression(s2t, vals2, loc);
  Bexpression *fex2 = be->struct_field_expression(sex2, 1, loc);
  h.mkAssign(vex2, fex2);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
  define void @foo(ptr nest %nest.0) #0 {
  entry:
    %tmp.0 = alloca { ptr, i32 }, align 8
    %x = alloca i32, align 4
    %y = alloca i32, align 4
    %z = alloca i32, align 4
    store i32 0, ptr %x, align 4
    store i32 0, ptr %y, align 4
    %y.ld.0 = load i32, ptr %y, align 4
    %field.0 = getelementptr inbounds { ptr, i32 }, ptr %tmp.0, i32 0, i32 0
    store ptr null, ptr %field.0, align 8
    %field.1 = getelementptr inbounds { ptr, i32 }, ptr %tmp.0, i32 0, i32 1
    store i32 %y.ld.0, ptr %field.1, align 4
    %field.2 = getelementptr inbounds { ptr, i32 }, ptr %tmp.0, i32 0, i32 1
    %.field.ld.0 = load i32, ptr %field.2, align 4
    store i32 %.field.ld.0, ptr %x, align 4
    store i32 0, ptr %z, align 4
    store i32 42, ptr %z, align 4
    ret void
  }
  )RAW_RESULT");

  bool broken = h.finish(StripDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");

  bool isOK = h.expectValue(func->function(), exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");
}

TEST_P(BackendArrayStructTests, TestArrayIndexingExprs) {
  auto cc = GetParam();
  // Testing array indexing expression for composites.
  FcnTestHarness h(cc);
  Llvm_backend *be = h.be();
  BFunctionType *befty = mkFuncTyp(be, L_END);
  Bfunction *func = h.mkFunction("foo", befty);

  // type T [4]int64
  Location loc;
  Bexpression *val4 = mkInt64Const(be, int64_t(4));
  Btype *bi64t = be->integer_type(false, 64);
  Btype *at4 = be->array_type(bi64t, val4);

  // Taking an element of non-constant composite.
  // var x, y int64
  // x = T{y, 3, 2, 1}[1]
  Bvariable *x = h.mkLocal("x", bi64t);
  Bvariable *y = h.mkLocal("y", bi64t);
  std::vector<unsigned long> indexes = { 0, 1, 2, 3 };
  std::vector<Bexpression *> vals1;
  vals1.push_back(be->var_expression(y, loc));
  vals1.push_back(mkInt64Const(be, 3));
  vals1.push_back(mkInt64Const(be, 2));
  vals1.push_back(mkInt64Const(be, 1));
  Bexpression *aex1 = be->array_constructor_expression(at4, indexes, vals1, loc);
  Bexpression *vex1 = be->var_expression(x, loc);
  Bexpression *bi32one = mkInt32Const(be, 1);
  Bexpression *eex1 = be->array_index_expression(aex1, bi32one, loc);
  h.mkAssign(vex1, eex1);

  // Taking an element of constant composite.
  // var z int64
  // z = T{4, 3, 2, 1}[1]
  Bvariable *z = h.mkLocal("z", bi64t);
  std::vector<Bexpression *> vals2;
  for (int64_t v : {4, 3, 2, 1})
    vals2.push_back(mkInt64Const(be, v));
  Bexpression *aex2 = be->array_constructor_expression(at4, indexes, vals2, loc);
  Bexpression *vex2 = be->var_expression(z, loc);
  Bexpression *eex2 = be->array_index_expression(aex2, bi32one, loc);
  h.mkAssign(vex2, eex2);

  // Taking an element of constant composite with non-constant index.
  // var w int64
  // w = T{4, 3, 2, 1}[x]
  Bvariable *w = h.mkLocal("w", bi64t);
  std::vector<Bexpression *> vals3;
  for (int64_t v : {4, 3, 2, 1})
    vals3.push_back(mkInt64Const(be, v));
  Bexpression *aex3 = be->array_constructor_expression(at4, indexes, vals3, loc);
  Bexpression *vex3 = be->var_expression(w, loc);
  Bexpression *iex3 = be->var_expression(x, loc);
  Bexpression *eex3 = be->array_index_expression(aex3, iex3, loc);
  h.mkAssign(vex3, eex3);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
  define void @foo(ptr nest %nest.0) #0 {
  entry:
    %tmp.0 = alloca [4 x i64], align 8
    %x = alloca i64, align 8
    %y = alloca i64, align 8
    %z = alloca i64, align 8
    %w = alloca i64, align 8
    store i64 0, ptr %x, align 8
    store i64 0, ptr %y, align 8
    %y.ld.0 = load i64, ptr %y, align 8
    %index.0 = getelementptr [4 x i64], ptr %tmp.0, i32 0, i32 0
    store i64 %y.ld.0, ptr %index.0, align 8
    %index.1 = getelementptr [4 x i64], ptr %tmp.0, i32 0, i32 1
    store i64 3, ptr %index.1, align 8
    %index.2 = getelementptr [4 x i64], ptr %tmp.0, i32 0, i32 2
    store i64 2, ptr %index.2, align 8
    %index.3 = getelementptr [4 x i64], ptr %tmp.0, i32 0, i32 3
    store i64 1, ptr %index.3, align 8
    %index.4 = getelementptr [4 x i64], ptr %tmp.0, i32 0, i32 1
    %.index.ld.0 = load i64, ptr %index.4, align 8
    store i64 %.index.ld.0, ptr %x, align 8
    store i64 0, ptr %z, align 8
    store i64 3, ptr %z, align 8
    store i64 0, ptr %w, align 8
    %x.ld.0 = load i64, ptr %x, align 8
    %index.5 = getelementptr [4 x i64], ptr @const.0, i32 0, i64 %x.ld.0
    %.index.ld.1 = load i64, ptr %index.5, align 8
    store i64 %.index.ld.1, ptr %w, align 8
    ret void
  }
  )RAW_RESULT");

  bool broken = h.finish(StripDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");

  bool isOK = h.expectValue(func->function(), exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");
}

TEST_P(BackendArrayStructTests, CreateArrayConstructionExprs) {
  auto cc = GetParam();
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();

  // var aa [4]int64 = { 4, 3, 2, 1 }
  Location loc;
  Bexpression *val4 = mkInt64Const(be, int64_t(4));
  Btype *bi64t = be->integer_type(false, 64);
  Btype *at4 = be->array_type(bi64t, val4);
  std::vector<unsigned long> indexes1 = { 0, 1, 2, 3 };
  std::vector<Bexpression *> vals1;
  for (int64_t v : {4, 3, 2, 1})
    vals1.push_back(mkInt64Const(be, v));
  Bexpression *arcon1 =
      be->array_constructor_expression(at4, indexes1, vals1, loc);
  h.mkLocal("aa", at4, arcon1);

  // var ab [4]int64 = { 2:3 }
  std::vector<unsigned long> indexes2 = { 2 };
  std::vector<Bexpression *> vals2;
  vals2.push_back(mkInt64Const(be, int64_t(3)));
  Bexpression *arcon2 =
    be->array_constructor_expression(at4, indexes2, vals2, loc);
  h.mkLocal("ab", at4, arcon2);

  // var ac [4]int64 = { 1:z }
  Bvariable *z = h.mkLocal("z", bi64t);
  std::vector<unsigned long> indexes3 = { 1 };
  std::vector<Bexpression *> vals3;
  vals3.push_back(be->var_expression(z, loc));
  Bexpression *arcon3 =
      be->array_constructor_expression(at4, indexes3, vals3, loc);
  h.mkLocal("ac", at4, arcon3);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %aa, ptr align 8 @const.0, i64 32, i1 false)
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %ab, ptr align 8 @const.1, i64 32, i1 false)
    store i64 0, ptr %z, align 8
    %z.ld.0 = load i64, ptr %z, align 8
    %index.0 = getelementptr [4 x i64], ptr %ac, i32 0, i32 0
    store i64 0, ptr %index.0, align 8
    %index.1 = getelementptr [4 x i64], ptr %ac, i32 0, i32 1
    store i64 %z.ld.0, ptr %index.1, align 8
    %index.2 = getelementptr [4 x i64], ptr %ac, i32 0, i32 2
    store i64 0, ptr %index.2, align 8
    %index.3 = getelementptr [4 x i64], ptr %ac, i32 0, i32 3
    store i64 0, ptr %index.3, align 8
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, CreateStructConstructionExprs) {
  auto cc = GetParam();
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();
  Bfunction *func = h.func();
  Location loc;

  // type X struct {
  //    f1 *int32
  //    f2 int32
  // }
  // func foo(param1, param2 int32) int64 {
  // var loc1 X = { nil, 101 }
  // var loc2 X = { &param1, loc1.f2 }

  // var loc1 X = { nil, 101 }
  Btype *bi32t = be->integer_type(false, 32);
  Btype *pbi32t = be->pointer_type(bi32t);
  Btype *s2t = mkBackendStruct(be, pbi32t, "f1", bi32t, "f2", nullptr);
  std::vector<Bexpression *> vals1;
  vals1.push_back(be->zero_expression(pbi32t));
  vals1.push_back(mkInt32Const(be, int32_t(101)));
  Bexpression *scon1 = be->constructor_expression(s2t, vals1, loc);
  Bvariable *loc1 = h.mkLocal("loc1", s2t, scon1);

  // var loc2 X = { &param1, loc1.f2 }
  Bvariable *p1 = func->getNthParamVar(0);
  Bexpression *ve1 = be->var_expression(p1, loc);
  Bexpression *adp = be->address_expression(ve1, loc);
  Bexpression *ve2 = be->var_expression(loc1, loc);
  Bexpression *fex = be->struct_field_expression(ve2, 1, loc);
  std::vector<Bexpression *> vals2;
  vals2.push_back(adp);
  vals2.push_back(fex);
  Bexpression *scon2 = be->constructor_expression(s2t, vals2, loc);
  h.mkLocal("loc2", s2t, scon2);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %loc1, ptr align 8 @const.0, i64 16, i1 false)
    %field.0 = getelementptr inbounds { ptr, i32 }, ptr %loc1, i32 0, i32 1
    %loc1.field.ld.0 = load i32, ptr %field.0, align 4
    %field.1 = getelementptr inbounds { ptr, i32 }, ptr %loc2, i32 0, i32 0
    store ptr %param1.addr, ptr %field.1, align 8
    %field.2 = getelementptr inbounds { ptr, i32 }, ptr %loc2, i32 0, i32 1
    store i32 %loc1.field.ld.0, ptr %field.2, align 4
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, CreateNestedStructConstructionExprs) {
  auto cc = GetParam();
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();
  Bfunction *func = h.func();
  Location loc;

  // type X struct {
  //    f1 *int32
  //    f2 int32
  // }
  // type Y struct {
  //    f1 X
  //    f2 float32
  // }
  Btype *bi32t = be->integer_type(false, 32);
  Btype *bf32t = be->float_type(32);
  Btype *pbi32t = be->pointer_type(bi32t);
  Btype *sxt = mkBackendStruct(be, pbi32t, "f1", bi32t, "f2", nullptr);
  Btype *syt = mkBackendStruct(be, sxt, "f1", bf32t, "f2", nullptr);

  // var l1 Y = Y{ X{nil, 3}, 3.0}
  std::vector<Bexpression *> vals1;
  Bvariable *p1 = func->getNthParamVar(0);
  Bexpression *ve1 = be->var_expression(p1, loc);
  Bexpression *adp = be->address_expression(ve1, loc);
  vals1.push_back(adp);
  vals1.push_back(mkInt32Const(be, int32_t(3)));
  Bexpression *scon1 = be->constructor_expression(sxt, vals1, loc);
  std::vector<Bexpression *> vals2;
  vals2.push_back(scon1);
  Bexpression *ci3 = mkInt32Const(be, int32_t(3));
  vals2.push_back(be->convert_expression(bf32t, ci3, loc));
  Bexpression *scon2 = be->constructor_expression(syt, vals2, loc);
  Bvariable *loc1 = h.mkLocal("loc1", syt);
  Bexpression *vex = be->var_expression(loc1, loc);
  h.mkAssign(vex, scon2);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %loc1, ptr align 8 @const.0, i64 24, i1 false)
    %field.0 = getelementptr inbounds { ptr, i32 }, ptr %tmp.0, i32 0, i32 0
    store ptr %param1.addr, ptr %field.0, align 8
    %field.1 = getelementptr inbounds { ptr, i32 }, ptr %tmp.0, i32 0, i32 1
    store i32 3, ptr %field.1, align 4
    %field.2 = getelementptr inbounds { { ptr, i32 }, float }, ptr %loc1, i32 0, i32 0
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %field.2, ptr align 8 %tmp.0, i64 16, i1 false)
    %field.3 = getelementptr inbounds { { ptr, i32 }, float }, ptr %loc1, i32 0, i32 1
    store float 3.000000e+00, ptr %field.3, align 4
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, CreateStructConstructionExprs2) {
  auto cc = GetParam();
  FcnTestHarness h(cc);
  Llvm_backend *be = h.be();

  Btype *bi32t = be->integer_type(false, 32);
  Btype *pbi32t = be->pointer_type(bi32t);
  Btype *s2t = mkBackendStruct(be, pbi32t, "f1", bi32t, "f2", nullptr);
  Btype *ps2t = be->pointer_type(s2t);
  BFunctionType *befty1 = mkFuncTyp(be,
                                    L_PARM, ps2t,
                                    L_PARM, pbi32t,
                                    L_END);
  Bfunction *func = h.mkFunction("blah", befty1);
  Location loc;

  // *p0 = { p1, 101 }
  Bvariable *p0 = func->getNthParamVar(0);
  Bvariable *p1 = func->getNthParamVar(1);
  Bexpression *ve = be->var_expression(p0, loc);
  Bexpression *dex = be->indirect_expression(s2t, ve, false, loc);
  std::vector<Bexpression *> vals;
  vals.push_back(be->var_expression(p1, loc));
  vals.push_back(mkInt32Const(be, int32_t(101)));
  Bexpression *scon = be->constructor_expression(s2t, vals, loc);
  h.mkAssign(dex, scon);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    %p0.ld.0 = load ptr, ptr %p0.addr, align 8
    %p1.ld.0 = load ptr, ptr %p1.addr, align 8
    %field.0 = getelementptr inbounds { ptr, i32 }, ptr %p0.ld.0, i32 0, i32 0
    store ptr %p1.ld.0, ptr %field.0, align 8
    %field.1 = getelementptr inbounds { ptr, i32 }, ptr %p0.ld.0, i32 0, i32 1
    store i32 101, ptr %field.1, align 4
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, CreateStructConstructionExprs3) {
  auto cc = GetParam();
  // Test struct construction involving global variables.
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();
  Location loc;

  // type T struct {
  //    f1 int32
  // }
  Btype *bi32t = be->integer_type(false, 32);
  Btype *s1t = mkBackendStruct(be, bi32t, "f1", nullptr);

  // Construct a struct with a global var field
  // var x int32  // global
  // var t = T{x} // global
  unsigned int emptyflags = 0;
  Bvariable *x = be->global_variable("x", "x", bi32t, emptyflags, loc);
  Bexpression *xvex = be->var_expression(x, loc);
  std::vector<Bexpression *> vals1 = {xvex};
  Bexpression *scon1 = be->constructor_expression(s1t, vals1, loc);
  Bvariable *t = be->global_variable("t", "t", s1t, emptyflags, loc);
  Bexpression *tvex = be->var_expression(t, loc);
  h.mkAssign(tvex, scon1);

  // Construct a struct with a field from a field of global var
  // var t2 = T{t.x}
  Bexpression *tvex2 = be->var_expression(t, loc);
  Bexpression *fex = be->struct_field_expression(tvex2, 0, loc);
  std::vector<Bexpression *> vals2 = {fex};
  Bexpression *scon2 = be->constructor_expression(s1t, vals2, loc);
  h.mkLocal("t2", s1t, scon2);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    %x.ld.0 = load i32, ptr @x, align 4
    store i32 %x.ld.0, ptr @t, align 4
    %t.field.ld.0 = load i32, ptr @t, align 4
    %field.2 = getelementptr inbounds { i32 }, ptr %t2, i32 0, i32 0
    store i32 %t.field.ld.0, ptr %field.2, align 4
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, CreateArrayIndexingExprs) {
  auto cc = GetParam();
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();

  // var aa [4]int64 = { 4, 3, 2, 1 }
  Location loc;
  Bexpression *val4 = mkInt64Const(be, int64_t(4));
  Btype *bi64t = be->integer_type(false, 64);
  Btype *at4 = be->array_type(bi64t, val4);
  std::vector<unsigned long> indexes1 = { 0, 1, 2, 3 };
  std::vector<Bexpression *> vals1;
  for (int64_t v : {4, 3, 2, 1})
    vals1.push_back(mkInt64Const(be, v));
  Bexpression *arcon1 =
    be->array_constructor_expression(at4, indexes1, vals1, loc);
  Bvariable *aa = h.mkLocal("aa", at4, arcon1);

  // aa[1]
  Bexpression *bi32one = mkInt32Const(be, 1);
  Bexpression *vea1 = be->var_expression(aa, loc);
  Bexpression *aa1 = be->array_index_expression(vea1, bi32one, loc);

  // aa[3]
  Bexpression *bi64three = mkInt64Const(be, 3);
  Bexpression *vea2 = be->var_expression(aa, loc);
  Bexpression *aa2 = be->array_index_expression(vea2, bi64three, loc);

  // aa[aa[3]]
  Bexpression *vea3 = be->var_expression(aa, loc);
  Bexpression *aa3 = be->array_index_expression(vea3, aa2, loc);

  // aa[aa[1]]
  Bexpression *vea4 = be->var_expression(aa, loc);
  Bexpression *aa4 = be->array_index_expression(vea4, aa1, loc);

  // aa[aa[1]] = aa[aa[3]]
  h.mkAssign(aa4, aa3);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %aa, ptr align 8 @const.0, i64 32, i1 false)
    %index.0 = getelementptr [4 x i64], ptr %aa, i32 0, i32 1
    %aa.index.ld.0 = load i64, ptr %index.0, align 8
    %index.1 = getelementptr [4 x i64], ptr %aa, i32 0, i64 %aa.index.ld.0
    %index.2 = getelementptr [4 x i64], ptr %aa, i32 0, i64 3
    %aa.index.ld.1 = load i64, ptr %index.2, align 8
    %index.3 = getelementptr [4 x i64], ptr %aa, i32 0, i64 %aa.index.ld.1
    %aa.index.ld.2 = load i64, ptr %index.3, align 8
    store i64 %aa.index.ld.2, ptr %index.1, align 8
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, CreateComplexIndexingAndFieldExprs) {
  auto cc = GetParam();
  FcnTestHarness h(cc, "foo");

  // Create type that incorporates structures, arrays, and pointers:
  //
  //   type sA struct {
  //      x, y int64
  //   }
  //   type asA [4]*sA
  //   type sB struct {
  //      y  bool
  //      ar asA
  //      n  bool
  //   }
  //   type psB *sB
  //   type t [10]psB
  //
  Llvm_backend *be = h.be();
  Btype *bi64t = be->integer_type(false, 64);
  Btype *sA = mkBackendStruct(be, bi64t, "x", bi64t, "y", nullptr);
  Btype *psA = be->pointer_type(sA);
  Bexpression *val4 = mkInt64Const(be, int64_t(4));
  Btype *asA = be->array_type(psA, val4);
  Btype *bt = be->bool_type();
  Btype *sB = mkBackendStruct(be, bt, "y", asA, "ar", bt, "n", nullptr);
  Btype *psB = be->pointer_type(sB);
  Bexpression *val10 = mkInt64Const(be, int64_t(10));
  Btype *t = be->array_type(psB, val10);
  Location loc;

  // var t1 t
  Bvariable *t1 = h.mkLocal("t1", t);

  // t1[7].ar[3].x = 5
  {
    Bexpression *vt = be->var_expression(t1, loc);
    Bexpression *bi32sev = mkInt32Const(be, 7);
    Bexpression *ti7 = be->array_index_expression(vt, bi32sev, loc);
    bool knValid = true;
    Bexpression *iti7 = be->indirect_expression(sB, ti7, knValid, loc);
    Bexpression *far = be->struct_field_expression(iti7, 1, loc);
    Bexpression *bi32three = mkInt32Const(be, 3);
    Bexpression *ar3 = be->array_index_expression(far, bi32three, loc);
    Bexpression *iar3 = be->indirect_expression(sA, ar3, knValid, loc);
    Bexpression *fx = be->struct_field_expression(iar3, 0, loc);
    Bexpression *bi64five = mkInt64Const(be, 5);
    h.mkAssign(fx, bi64five);

    DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
      call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %t1, ptr align 8 @const.0, i64 80, i1 false)
      %index.0 = getelementptr [10 x ptr], ptr %t1, i32 0, i32 7
      %field.0 = getelementptr inbounds { i8, [4 x ptr], i8 }, ptr %index.0, i32 0, i32 1
      %index.1 = getelementptr [4 x ptr], ptr %field.0, i32 0, i32 3
      %field.1 = getelementptr inbounds { i64, i64 }, ptr %index.1, i32 0, i32 0
      store i64 5, ptr %field.1, align 8
    )RAW_RESULT");

    bool isOK = h.expectBlock(exp);
    EXPECT_TRUE(isOK && "Block does not have expected contents");
  }

  h.newBlock();

  // q := t1[0].ar[0].y
  {
    Bexpression *vt = be->var_expression(t1, loc);
    Bexpression *bi32zero = mkInt32Const(be, 0);
    Bexpression *ti0 = be->array_index_expression(vt, bi32zero, loc);
    bool knValid = true;
    Bexpression *iti0 = be->indirect_expression(sB, ti0, knValid, loc);
    Bexpression *far = be->struct_field_expression(iti0, 1, loc);
    Bexpression *ar3 = be->array_index_expression(far, bi32zero, loc);
    Bexpression *iar3 = be->indirect_expression(sA, ar3, knValid, loc);
    Bexpression *fx = be->struct_field_expression(iar3, 1, loc);
    h.mkLocal("q", bi64t, fx);

    DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
      %index.2 = getelementptr [10 x ptr], ptr %t1, i32 0, i32 0
      %field.2 = getelementptr inbounds { i8, [4 x ptr], i8 }, ptr %index.2, i32 0, i32 1
      %index.3 = getelementptr [4 x ptr], ptr %field.2, i32 0, i32 0
      %field.3 = getelementptr inbounds { i64, i64 }, ptr %index.3, i32 0, i32 1
      %.field.ld.0 = load i64, ptr %field.3, align 8
      store i64 %.field.ld.0, ptr %q, align 8
    )RAW_RESULT");

    bool isOK = h.expectBlock(exp);
    EXPECT_TRUE(isOK && "Block does not have expected contents");
  }

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, TestStructAssignment) {
  auto cc = GetParam();
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();

  // type T1 struct { f1 bool }
  // type T2 struct { f1, f2, f3, f4, f5, f6 int64 }
  Location loc;
  Btype *bt = be->bool_type();
  Btype *pbt = be->pointer_type(bt);
  Btype *bi64t = be->integer_type(false, 64);
  Btype *s1t = mkBackendStruct(be, pbt, "f1", nullptr);
  Btype *s2t = mkBackendStruct(be, bi64t, "f1", bi64t, "f2", bi64t, "f3",
                               bi64t, "f4", bi64t, "f5", bi64t, "f6", nullptr);

  // var x1, y1 T1
  // var x2, y2 T2
  Bvariable *x1 = h.mkLocal("x1", s1t);
  Bvariable *y1 = h.mkLocal("y1", s1t);
  Bvariable *x2 = h.mkLocal("x2", s2t);
  Bvariable *y2 = h.mkLocal("y2", s2t);

  // x1 = y1
  // x2 = y2
  Bexpression *ve1 = be->var_expression(x1, loc);
  Bexpression *ve2 = be->var_expression(y1, loc);
  h.mkAssign(ve1, ve2);
  Bexpression *ve3 = be->var_expression(x2, loc);
  Bexpression *ve4 = be->var_expression(y2, loc);
  h.mkAssign(ve3, ve4);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %x1, ptr align 8 @const.0, i64 8, i1 false)
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %y1, ptr align 8 @const.0, i64 8, i1 false)
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %x2, ptr align 8 @const.1, i64 48, i1 false)
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %y2, ptr align 8 @const.1, i64 48, i1 false)
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %x1, ptr align 8 %y1, i64 8, i1 false)
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 8 %x2, ptr align 8 %y2, i64 48, i1 false)
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

TEST_P(BackendArrayStructTests, TestStructFieldAddressExpr) {
  auto cc = GetParam();
  // Test address expression of struct field.
  FcnTestHarness h(cc, "foo");
  Llvm_backend *be = h.be();
  Location loc;

  // type T struct {
  //    f1 int32
  // }
  Btype *bi32t = be->integer_type(false, 32);
  Btype *bpi32t = be->pointer_type(bi32t);
  Btype *s1t = mkBackendStruct(be, bi32t, "f1", nullptr);

  // var t1 T // local
  // var t2 T // global
  // var a1 = &t1.f1
  // var a2 = &t2.f1
  Bvariable *t1 = h.mkLocal("t1", s1t);
  Bexpression *t1vex = be->var_expression(t1, loc);
  Bexpression *fex1 = be->struct_field_expression(t1vex, 0, loc);
  Bexpression *aex1 = be->address_expression(fex1, loc);
  h.mkLocal("a1", bpi32t, aex1);

  unsigned int t2flags = 0;
  Bvariable *t2 = be->global_variable("t2", "t2", s1t, t2flags, loc);
  Bexpression *t2vex = be->var_expression(t2, loc);
  Bexpression *fex2 = be->struct_field_expression(t2vex, 0, loc);
  Bexpression *aex2 = be->address_expression(fex2, loc);
  h.mkLocal("a2", bpi32t, aex2);

  DECLARE_EXPECTED_OUTPUT(exp, R"RAW_RESULT(
    call addrspace(0) void @llvm.memcpy.p0.p0.i64(ptr align 4 %t1, ptr align 4 @const.0, i64 4, i1 false)
    %field.0 = getelementptr inbounds { i32 }, ptr %t1, i32 0, i32 0
    store ptr %field.0, ptr %a1, align 8
    store ptr @t2, ptr %a2, align 8
  )RAW_RESULT");

  bool isOK = h.expectBlock(exp);
  EXPECT_TRUE(isOK && "Block does not have expected contents");

  bool broken = h.finish(PreserveDebugInfo);
  EXPECT_FALSE(broken && "Module failed to verify.");
}

} // namespace
