# -*- Python -*-

import os
import platform
import re
import subprocess
import locale

import lit.formats
import lit.util

from lit.llvm import llvm_config

# Configuration file for the 'lit' test runner.

# name: The name of this test suite.
config.name = 'gollvm'

# testFormat: The test format to use to interpret tests.
#
# For now we require '&&' between commands, until they get globally killed and the test runner updated.
config.test_format = lit.formats.ShTest(not llvm_config.use_lit_shell)

# suffixes: A list of file extensions to treat as test files.
config.suffixes = ['.ll', '*.s', '.go']

# excludes: A list of directories to exclude from the testsuite. The 'Inputs'
# subdirectories contain auxiliary inputs for various tests in their parent
# directories.
config.excludes = ['Inputs']

# test_source_root: The root path where tests are located.
config.test_source_root = os.path.dirname(__file__)

config.test_exec_root = os.path.join(config.gollvm_obj_root, 'test')

llvm_config.use_default_substitutions()

tool_patterns = ['llvm-goc', 'not', 'llvm-dis', 'llvm-readelf']

llvm_config.add_tool_substitutions(tool_patterns)
llvm_config.config.substitutions.extend([('%B', config.gollvm_obj_root)])

# Running on ELF based *nix
if platform.system() in ['FreeBSD', 'NetBSD', 'Linux']:
    config.available_features.add('system-linker-elf')

# Set if host-cxxabi's demangler can handle target's symbols.
if platform.system() not in ['Windows']:
    config.available_features.add('demangler')

llvm_config.feature_config(
    [('--targets-built', {'AArch64': 'aarch64',
                          'AMDGPU': 'amdgpu',
                          'ARM': 'arm',
                          'AVR': 'avr',
                          'Hexagon': 'hexagon',
                          'Mips': 'mips',
                          'MSP430': 'msp430',
                          'PowerPC': 'ppc',
                          'RISCV': 'riscv',
                          'Sparc': 'sparc',
                          'WebAssembly': 'wasm',
                          'X86': 'x86'})
     ])

