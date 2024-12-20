//===-- go-sha1.cpp -------------------------------------------------------===//
//
// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
//===----------------------------------------------------------------------===//
//
// Implements LLVM-specific sha1 utilities for use by the gofrontend code.
//

#include "go-sha1.h"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/SHA1.h"

class Llvm_Sha1_Helper : public Go_sha1_helper
{
 public:

  Llvm_Sha1_Helper() : ctx_(new llvm::SHA1()) { }

  ~Llvm_Sha1_Helper();

  // Incorporate 'len' bytes from 'buffer' into checksum.
  void process_bytes(const void* buffer, size_t len);

  // Finalize checksum and return in the form of a string.
  std::string finish();

 private:
  std::unique_ptr<llvm::SHA1> ctx_;
};

Llvm_Sha1_Helper::~Llvm_Sha1_Helper()
{
}

void
Llvm_Sha1_Helper::process_bytes(const void* buffer, size_t len)
{
  uint8_t *data = static_cast<uint8_t*>(const_cast<void*>(buffer));
  llvm::ArrayRef<uint8_t> aref(data, len);
  ctx_->update(aref);
}

std::string
Llvm_Sha1_Helper::finish()
{
  auto arr = ctx_->final();
  std::string result(std::begin(arr), std::begin(arr) + checksum_len);
  return result;
}

Go_sha1_helper*
go_create_sha1_helper()
{
  return new Llvm_Sha1_Helper();
}
