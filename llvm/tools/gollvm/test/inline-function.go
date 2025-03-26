// RUN: llvm-goc -flto=full -c %p/Inputs/longfun.go -o %t-pkg.o
// RUN: llvm-objcopy -j .go_export %t-pkg.o %t-pkg.gox
// RUN: echo 'packagefile longfun=%t-pkg.gox' > %t-importcfg
// RUN: llvm-goc -flto=full -c %s -fgo-importcfg=%t-importcfg -o %t.o
// RUN: llvm-goc -L%B/tools/gollvm/libgo -flto=full %t.o %t-pkg.o -Wl,--plugin-opt=save-temps -o %t-out
// RUN: llvm-dis %t-out.0.5.precodegen.bc -o - | FileCheck %s

// Check that PrintNums function has been inlined.
// CHECK:      define dso_local void @main.main(ptr nest {{.*}} %nest.0) {{.*}} {
// CHECK-NEXT: entry:
// CHECK-NEXT:     #dbg_value
// CHECK-NEXT:   call void @runtime.printlock(ptr nest undef), !dbg
// CHECK-NEXT:   call void @runtime.printint(ptr nest undef, i64 10), !dbg
// CHECK-NEXT:   call void @runtime.printnl(ptr nest undef), !dbg

package main

import "longfun"

func main() {
  longfun.PrintNums(10)
}
