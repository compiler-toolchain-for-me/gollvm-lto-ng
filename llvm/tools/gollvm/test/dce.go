// Check elimination of unused exported symbol main.Bar when LTO is enabled.

// RUN: llvm-goc -L%B/tools/gollvm/libgo %s %p/Inputs/dce-foobar.go -o %t
// RUN: llvm-goc -L%B/tools/gollvm/libgo -flto %s %p/Inputs/dce-foobar.go -o %t.lto
// RUN: llvm-goc -L%B/tools/gollvm/libgo -flto=thin %s %p/Inputs/dce-foobar.go -o %t.thin.lto
// RUN: llvm-readelf -s %t | FileCheck %s --check-prefix=REGULAR
// RUN: llvm-readelf -s %t | FileCheck %s --check-prefix=REGULAR
// RUN: llvm-readelf -s %t.lto | FileCheck %s --check-prefix=LTO
// RUN: llvm-readelf -s %t.thin.lto | FileCheck %s --check-prefix=LTO

// REGULAR: main.Bar
// LTO-NOT: main.Bar

package main

func main() {
  Foo()
}
