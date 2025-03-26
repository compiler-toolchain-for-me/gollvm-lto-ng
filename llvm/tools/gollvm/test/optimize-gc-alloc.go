// RUN: llvm-goc -flto -L%B/tools/gollvm/libgo -Wl,-plugin-opt=save-temps -static-libgo %s -o %t
// RUN: llvm-dis %t.0.5.precodegen.bc -o - | FileCheck %s --check-prefix=REGULAR

// RUN: llvm-goc -flto -fexperimental-optimize-gc-allocs -L%B/tools/gollvm/libgo -Wl,-plugin-opt=save-temps -static-libgo %s -o %t-gcopt
// RUN: llvm-dis %t-gcopt.0.5.precodegen.bc -o - | FileCheck %s --check-prefix=GCOPT

// REGULAR-LABEL: define dso_local void @main.main(ptr nest {{.*}} %nest.2)
// REGULAR:       %call.573.i = call noalias noundef nonnull ptr @runtime.mallocgc(ptr nest poison, i64 8, ptr nonnull @int..d, i8 zeroext 1) #[[ATTR:[0-9]+]]
// REGULAR:       store i64 42, ptr %call.573.i, align 8
// REGULAR:  attributes #[[ATTR]] = { allockind("alloc,zeroed")

// GCOPT-LABEL: define dso_local void @main.main(ptr nest {{.*}} %nest.2)
// GCOPT:  %tmpv.gcopt1 = alloca [8 x i8], align 8
// GCOPT:  store i64 42, ptr %tmpv.gcopt1, align 8 

package main

func foo() *int {
  x := 42
  return &x
}

//go:noinline
func bar(p *int) {
  println(*p)
}

func main() {
  p := foo()
  bar(p)
}
