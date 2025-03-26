// RUN: llvm-goc -flto=full -c %p/Inputs/foobar-noinline.go -o %t-pkg.o
// RUN: llvm-objcopy -j .go_export %t-pkg.o %t-pkg.gox
// RUN: echo 'packagefile foobar=%t-pkg.gox' > %t-importcfg

// RUN: llvm-goc -S -emit-llvm -O2 -fgo-importcfg=%t-importcfg %s -o - | FileCheck %s --check-prefix=NOLTO

// RUN: llvm-goc -flto=full -c %s -fgo-importcfg=%t-importcfg -o %t.o
// RUN: llvm-goc -L%B/tools/gollvm/libgo -flto=full %t.o %t-pkg.o -Wl,--plugin-opt=save-temps -o %t-out

// RUN: llvm-dis %t-out.0.5.precodegen.bc -o - | FileCheck %s --check-prefix=LTO

// NOLTO:      define void @main.main(ptr nest {{.*}} %nest.0) {{.*}} {
// NOLTO-NEXT: entry:
// NOLTO-NEXT:     #dbg_value
// NOLTO-NEXT:     #dbg_value
// NOLTO-NEXT:   %main.__g.ld.0 = load i64, ptr @main.__g, align 8, !dbg
// NOLTO-NEXT:   %icmp.0 = icmp eq i64 %main.__g.ld.0, 0, !dbg
// NOLTO-NEXT:   %go_0foobar.Foo..f.go_0foobar.Bar..f = select i1 %icmp.0, ptr @go_0foobar.Foo..f, ptr @go_0foobar.Bar..f
// NOLTO-NEXT:   %. = select i1 %icmp.0, i64 10, i64 20
// NOLTO-NEXT:     #dbg_value
// NOLTO-NEXT:     #dbg_value
// NOLTO-NEXT:   %deref.ld.0 = load ptr, ptr %go_0foobar.Foo..f.go_0foobar.Bar..f, align 8, !dbg
// NOLTO-NEXT:   call void %deref.ld.0(ptr nest nonnull %go_0foobar.Foo..f.go_0foobar.Bar..f, i64 %.), !dbg

// LTO:      define dso_local void @main.main(ptr nest {{.*}} %nest.0) {{.*}} {
// LTO-NEXT: entry:
// LTO-NEXT:   #dbg_value
// LTO-NEXT:   #dbg_value
// LTO-NEXT:   #dbg_value
// LTO-NEXT:   #dbg_value
// LTO-NEXT:   call fastcc void @go_0foobar.Foo(i64 10), !dbg

package main

import "foobar"

var _g int

func main() {
  var pfunc func(int)
  var val int
  if (_g == 0) {
     pfunc = foobar.Foo
     val = 10
  } else {
     pfunc = foobar.Bar
     val = 20
  }
  pfunc(val)
}
