// RUN: llvm-goc -flto=full -c %p/Inputs/foo-noinline.go -o %t-pkg.o
// RUN: llvm-objcopy -j .go_export %t-pkg.o %t-pkg.gox
// RUN: echo 'packagefile foo=%t-pkg.gox' > %t-importcfg
// RUN: llvm-goc -flto=full -c %s -fgo-importcfg=%t-importcfg -o %t.o
// RUN: llvm-goc -L%B/tools/gollvm/libgo -flto=full -fmerge-functions %t.o %t-pkg.o -Wl,--plugin-opt=save-temps -o %t-out

// RUN: llvm-dis %t-out.0.5.precodegen.bc -o - | FileCheck %s

// CHECK:      define dso_local void @main.main(ptr nest {{.*}} %nest.1) {{.*}} {
// CHECK-NEXT: entry:
// CHECK-NEXT:   call fastcc void @go_0foo.Foo(), !dbg
// CHECK-NEXT:   call fastcc void @go_0foo.Foo(), !dbg

package main

import "foo"

//go:noinline
func Bar(i int) {
  println(i)
}

func main() {
  Bar(10)
  foo.Foo(10)
}
