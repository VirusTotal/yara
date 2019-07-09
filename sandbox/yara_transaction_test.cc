/*
Copyright (c) 2019. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "sandbox/yara_transaction.h"

#include <asm/unistd.h>  // __NR_memdfd_create
#include <unistd.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/str_cat.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "sandbox/yara_matches.pb.h"
#include "sandboxed_api/util/status_matchers.h"
#include "sandboxed_api/util/statusor.h"

using ::sapi::IsOk;
using ::testing::Eq;
using ::testing::StrEq;

namespace yara {
namespace {

// Wraps an in-memory file descriptor created by memfd_create().
class MemoryFD {
 public:
  static ::sapi::StatusOr<MemoryFD> CreateWithContent(
      absl::string_view content) {
    MemoryFD mem_fd;
    // Avoid dependency on UAPI headers
    constexpr uintptr_t MFD_CLOEXEC = 0x0001U;
    constexpr const char* kName = "memfd";
    mem_fd.fd_ = syscall(__NR_memfd_create, reinterpret_cast<uintptr_t>(kName),
                         MFD_CLOEXEC);
    if (mem_fd.fd_ == -1) {
      return ::sapi::UnknownError(absl::StrCat("memfd(): ", strerror(errno)));
    }
    if (ftruncate(mem_fd.fd_, content.size()) == -1) {
      return ::sapi::UnknownError(
          absl::StrCat("ftruncate(): ", strerror(errno)));
    }
    while (!content.empty()) {
      ssize_t written =
          TEMP_FAILURE_RETRY(write(mem_fd.fd_, content.data(), content.size()));
      if (written <= 0) {
        return ::sapi::UnknownError(absl::StrCat("write(): ", strerror(errno)));
      }
      content.remove_prefix(written);
    }
    return mem_fd;
  }

  MemoryFD(MemoryFD&& other) { *this = std::move(other); }

  MemoryFD& operator=(MemoryFD&& other) {
    fd_ = other.fd_;
    other.fd_ = 0;
    return *this;
  }

  ~MemoryFD() {
    if (fd_ > 0) {
      close(fd_);
    };
  }

  int fd() const { return fd_; }

 private:
  MemoryFD() = default;
  int fd_;
};

class TransactionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    SAPI_ASSERT_OK_AND_ASSIGN(
        transaction_,
        YaraTransaction::Create(YaraTransaction::Options{}
                                    .set_scan_timeout(absl::Minutes(1))
                                    .set_num_workers(16)));
  }

  ::sapi::StatusOr<YaraMatches> ScanString(absl::string_view content) {
    SAPI_ASSIGN_OR_RETURN(MemoryFD mem_fd,
                          MemoryFD::CreateWithContent(content));
    return transaction_->ScanFd(mem_fd.fd());
  }

  std::unique_ptr<YaraTransaction> transaction_;
};

TEST_F(TransactionTest, BasicFunctionality) {
  ASSERT_THAT(transaction_
                  ->LoadRules(R"(
    rule Number {
      strings:   $ = "123"
      condition: all of them
    }
    rule Color {
      strings:   $ = "green"
      condition: all of them
    }
    rule Keyboard {
      strings:   $ = "dvorak"
      condition: all of them
    })")

                  .ValueOrDie(),
              Eq(3));

  SAPI_ASSERT_OK_AND_ASSIGN(YaraMatches matches, ScanString("qwerty 123"));

  EXPECT_THAT(matches.match_size(), Eq(1));
  EXPECT_THAT(matches.match(0).id().rule_name(), StrEq("Number"));

  SAPI_ASSERT_OK_AND_ASSIGN(matches, ScanString("green dvorak 456"));
  EXPECT_THAT(matches.match_size(), Eq(2));
  EXPECT_THAT(matches.match(0).id().rule_name(), StrEq("Color"));
  EXPECT_THAT(matches.match(1).id().rule_name(), StrEq("Keyboard"));
}

TEST_F(TransactionTest, ConcurrentScanStressTest) {
  ASSERT_THAT(transaction_
                  ->LoadRules(R"(
    rule Simple {
      strings:   $ = "A"
      condition: all of them
    })")
                  .ValueOrDie(),
              Eq(1));

  // Large number of threads during testing to increase likelihood of exposing
  // race conditions in threading code.
  constexpr int kThreads = 64;

  std::vector<std::thread> bundle;
  for (int i = 0; i < kThreads; ++i) {
    bundle.emplace_back([this, i]() {
      std::string buf((i + 1) * 102400, 'B');
      buf.append("A");  // Force the match to be at the very end
      SAPI_ASSERT_OK_AND_ASSIGN(YaraMatches matches, ScanString(buf));
      ASSERT_THAT(matches.match_size(), Eq(1));
      EXPECT_THAT(matches.match(0).id().rule_name(), StrEq("Simple"));
    });
  }
  for (auto& thread : bundle) {
    thread.join();
  }
}

}  // namespace
}  // namespace yara
