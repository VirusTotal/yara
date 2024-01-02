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

#ifndef SANDBOX_TRANSACTION_H_
#define SANDBOX_TRANSACTION_H_

#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "sandbox/yara_matches.pb.h"
#include "sandbox/yara_sapi.sapi.h"
#include "sandboxed_api/sandbox.h"
#include "sandboxed_api/sandbox2/executor.h"
#include "sandboxed_api/sandbox2/policy.h"
#include "sandboxed_api/sandbox2/util.h"
#include "sandboxed_api/sandbox2/util/bpf_helper.h"
#include "sandboxed_api/transaction.h"

namespace yara {

class YaraSandbox : public sandbox::YaraSandbox {
 public:
  std::unique_ptr<sandbox2::Policy> ModifyPolicy(
      sandbox2::PolicyBuilder* builder) override {
    return (*builder)
        .AllowStaticStartup()
        .AllowMmap()
        .AllowFork()  // Thread creation
        .AllowSyscalls({
            __NR_madvise,
            __NR_mprotect,
            __NR_munlock,
            __NR_poll,
            __NR_sched_getparam,
            __NR_sched_getscheduler,
            __NR_sched_yield,
        })
        .BuildOrDie();
  }

  void ModifyExecutor(sandbox2::Executor* executor) override {
    (*executor->limits())
        // Remove limit on file descriptor bytes.
        .set_rlimit_fsize(RLIM64_INFINITY)
        // Wall-time limit per call will be enforced by the Transaction.
        .set_rlimit_cpu(RLIM64_INFINITY);
  }
};

// Transaction class to run sandboxed Yara scans of the contents of file
// descriptors. This class is thread-safe and access to the sandboxee is
// multiplexed so that multiple threads can share the transaction.
class YaraTransaction : public ::sapi::Transaction {
 public:
  struct Options {
    absl::Duration scan_timeout;
    int num_workers;

    Options& set_scan_timeout(absl::Duration value) {
      scan_timeout = value;
      return *this;
    }

    Options& set_num_workers(int value) {
      num_workers = value;
      return *this;
    }
  };

  // Creates and initializes an instance of this transaction class with the
  // specified scan_timeout.
  static ::sapi::StatusOr<std::unique_ptr<YaraTransaction>> Create(
      Options options = {});

  // Loads new Yara rules into the sandboxee. Returns the number of rules
  // loaded. Only one set of rules can be active at any given time. This method
  // blocks until all concurrent YARA scans are completed before updating the
  // rules.
  ::sapi::StatusOr<int> LoadRules(const std::string& rule_string)
      LOCKS_EXCLUDED(mutex_);

  // Scans the contents of the specified file descriptor.
  // Returns DeadlineExceededError if the scan timed out.
  ::sapi::StatusOr<YaraMatches> ScanFd(int fd) LOCKS_EXCLUDED(mutex_);

 private:
  explicit YaraTransaction(absl::Duration scan_timeout)
      : ::sapi::Transaction(absl::make_unique<YaraSandbox>()) {}

  // Mutex to guard communication with the sandboxee
  static absl::Mutex mutex_;

  absl::Duration scan_timeout_;
};

}  // namespace yara

#endif  // SANDBOX_TRANSACTION_H_
