include (GoVars)

configure_file(src/goinstrument/goinstrument.go src/goinstrument/goinstrument.go @ONLY)

# Install libclang_rt.profile.a
set(llvm_dir ${GOLLVM_INSTALL_LIBDIR}/../lib/clang/15.0.0/lib/linux)
set(prof_lib ${GOLLVM_INSTALL_LIBDIR}/libclang_rt.profile.a)
set(prof_lib_arch ${llvm_dir}/libclang_rt.profile-${llarch}.a)

add_custom_command(
  OUTPUT ${prof_lib}
  COMMAND ${CMAKE_COMMAND} -E copy ${prof_lib_arch} ${prof_lib}
  DEPENDS install-profile
)

add_custom_target(proflib ALL DEPENDS ${prof_lib})

install(
  PROGRAMS ${prof_lib}
  COMPONENT proflib
  DESTINATION ${GOLLVM_INSTALL_LIBDIR})

add_custom_target(
  install-proflib
  DEPENDS ${prof_lib}
  COMMAND "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=proflib -P
          "${CMAKE_BINARY_DIR}/cmake_install.cmake")

# Go tool would be invoked to build/install package into a_dest_dir
set(go "${CMAKE_CURRENT_BINARY_DIR}/../gotools/go")
set(a_dest_dir "${CMAKE_CURRENT_BINARY_DIR}/pkg/gccgo_${goos}_${goarch}")

# Environment to invoke the go tool
set(env_go GO111MODULE=off GOPATH=${CMAKE_CURRENT_BINARY_DIR})
set(env_libp LD_LIBRARY_PATH=$ENV{LD_LIBRARY_PATH}:${CMAKE_CURRENT_BINARY_DIR}/../libgo)
set(env_path PATH=${llvm_dir}/bin:$ENV{PATH})
set(env_goroot GOROOT=${CMAKE_BINARY_DIR})
set(env ${env_go} ${env_libp} ${env_path} ${env_goroot})

macro(add_static_package package a_name flags)
  set(a_path "${a_dest_dir}/${a_name}")
  separate_arguments(split_flags UNIX_COMMAND "${flags}")

  add_custom_command(
    OUTPUT ${a_path}
    COMMAND ${env} ${go} install ${split_flags} ${package}
    DEPENDS ${gocompiler} gotools_all install-proflib install-gollvm
    COMMENT "Building static package '${a_name}'"
    VERBATIM)

  add_custom_target(${a_name} ALL DEPENDS ${a_path})
  set_target_properties(${a_name} PROPERTIES FOLDER "Object Libraries")

  # Configure for install.
  install(
    PROGRAMS ${a_path}
    COMPONENT ${a_name}
    DESTINATION ${GOLLVM_INSTALL_LIBDIR})

  add_custom_target(
    install-${a_name}
    DEPENDS ${a_name}
    COMMAND "${CMAKE_COMMAND}" -DCMAKE_INSTALL_COMPONENT=${a_name} -P
            "${CMAKE_BINARY_DIR}/cmake_install.cmake")

  add_dependencies(staticpkg ${a_name} install-proflib)
  add_dependencies(install-staticpkg install-${a_name})
endmacro()

add_custom_target(staticpkg)
add_custom_target(install-staticpkg DEPENDS staticpkg)

add_static_package("goinstrument"
                   "libgoinstrument.a"
                   "-a -gccgoflags 'all=-O2'")

