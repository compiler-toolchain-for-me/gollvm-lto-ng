// RUN: llvm-goc -### -flto %s 2>&1 | FileCheck %s --check-prefix=REGULARLTO
// RUN: llvm-goc -### -flto=full %s 2>&1 | FileCheck %s --check-prefix=REGULARLTO
// RUN: llvm-goc -### -flto=thin %s 2>&1 | FileCheck %s --check-prefix=THINLTO
// RUN: llvm-goc -### -flto -fmerge-functions %s 2>&1 | FileCheck %s --check-prefix=REGULARLTO-MF
// RUN: llvm-goc -### -flto=full -fmerge-functions %s 2>&1 | FileCheck %s --check-prefix=REGULARLTO-MF
// RUN: llvm-goc -### -flto=thin -fmerge-functions %s 2>&1 | FileCheck %s --check-prefix=THINLTO-MF

// REGULARLTO: "--plugin={{.*}}/lib/LLVMgold.so" "--plugin-opt=unifiedlto" "--eh-frame-hdr"
// REGULARLTO: {{.*}} "-L{{.*}}lib/clang/{{.*}}/x86_64-unknown-linux-gnu"
// THINLTO: "--plugin={{.*}}/lib/LLVMgold.so" "--plugin-opt=unifiedlto" "--plugin-opt=thinlto" "--eh-frame-hdr"
// THINLTO: {{.*}} "-L{{.*}}lib/clang/{{.*}}/x86_64-unknown-linux-gnu"
// REGULARLTO-MF: "--plugin={{.*}}/lib/LLVMgold.so" "--plugin-opt=unifiedlto" "--plugin-opt=merge-functions" "--eh-frame-hdr"
// REGULARLTO-MF: {{.*}} "-L{{.*}}lib/clang/{{.*}}/x86_64-unknown-linux-gnu"
// THINLTO-MF: "--plugin={{.*}}/lib/LLVMgold.so" "--plugin-opt=unifiedlto" "--plugin-opt=thinlto" "--plugin-opt=merge-functions"
// THINLTO-MF: "--eh-frame-hdr" {{.*}} "-L{{.*}}lib/clang/{{.*}}/x86_64-unknown-linux-gnu"
