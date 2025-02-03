// RUN: llvm-goc -L%B/tools/gollvm/libgo -flto -c %s -o %t.o
// RUN: llvm-objcopy --dump-section .llvm.lto=%t.lto.bc %t.o
// RUN: llvm-dis %t.lto.bc -o - | FileCheck %s

// All calls in init function must have debug info for LTO to work properly
// CHECK:      define void @__go_init_main(ptr nest nocapture readnone {{.*}}) {{.*}} {
// CHECK-NEXT: entry:
// CHECK-NEXT:   call void @runtime.registerTypeDescriptors(ptr nest undef, i64 11, ptr nonnull @go..typelists), !dbg
// CHECK-NEXT:   call void @internal_1cpu..import(ptr nest undef) #[[ID:[0-9]+]], !dbg
// CHECK-NEXT:   call void @runtime..import(ptr nest undef) #[[ID:[0-9]+]], !dbg

// Calls from package initializer (except first one) shouldn't be inlined
// CHECK: attributes #[[ID]] = { noinline }
// Check that we have embedded summary index and module hash is not zero.
// CHECK: module: (path: {{.*}}, hash: ({{[1-9][0-9]*}}, {{[1-9][0-9]*}}, {{[1-9][0-9]*}}, {{[1-9][0-9]*}}, {{[1-9][0-9]*}}))

package main

func main() {
  println("hello world")
}
