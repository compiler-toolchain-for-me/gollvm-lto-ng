// RUN: llvm-mc --triple=aarch64-linux-gnu -filetype=obj %p/Inputs/gort-symbols.s -o %t-gort.o
// RUN: llvm-goc --target=aarch64-linux-gnu -Oz -flto=full -c %p/Inputs/outline.go -o %t-pkg.o
// RUN: llvm-objcopy -j .go_export %t-pkg.o %t-pkg.gox
// RUN: echo 'packagefile outline=%t-pkg.gox' > %t-importcfg
// RUN: llvm-goc --target=aarch64-linux-gnu -Oz -flto=full -c %s -fgo-importcfg=%t-importcfg -o %t.o
// RUN: llvm-goc -nostdlib -L%B/tools/gollvm/libgo --target=aarch64-linux-gnu -flto=full -Wl,-u,main.main %t.o %t-pkg.o %t-gort.o -o %t-out
// RUN: llvm-objdump -d %t-out | FileCheck %s

// CHECK-LABEL: {{.*}} <main.main>:
// CHECK:      {{.*}} bl {{.*}} <OUTLINED_FUNCTION_0>
// CHECK-NEXT: {{.*}} bl {{.*}} <OUTLINED_FUNCTION_0>
// CHECK-NEXT: {{.*}} bl {{.*}} <OUTLINED_FUNCTION_0>
// CHECK-NEXT: {{.*}} bl {{.*}} <OUTLINED_FUNCTION_0>
// CHECK-NEXT: {{.*}} bl {{.*}} <OUTLINED_FUNCTION_0>
// CHECK-NEXT: {{.*}} bl {{.*}} <OUTLINED_FUNCTION_0>

// CHECK-LABEL: {{.*}} <OUTLINED_FUNCTION_0>:
// CHECK-NEXT: {{.*}} sub
// CHECK-NEXT: {{.*}} eor
// CHECK-NEXT: {{.*}} lsl

package main

import (
	"../tools/gollvm/libgo/math/rand"
	"outline"
)

var _g int

func main() {
	outline.PrintNums(rand.Int())
}
