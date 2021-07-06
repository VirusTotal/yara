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

#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <memory>
#include <queue>
#include <string>
#include <thread>

#include "absl/base/attributes.h"
#include "absl/container/node_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "libyara/include/yara.h"
#include "sandbox/collect_matches.h"
#include "sandbox/yara_matches.pb.h"

namespace yara
{
namespace
{
struct ScanTask
{
  // Key into the g_results map, used by YaraGetScanResult()
  uint64_t result_id;

  // File descriptor containing the data to scan
  int data_fd;

  // File descriptor used to signal the host code on scan completion
  int event_fd;

  // Scan timeout. YARA only supports second granularity.
  absl::Duration timeout;
};

struct ScanResult
{
  int code;
  YaraMatches matches;
};

static const bool g_init_done ABSL_ATTRIBUTE_UNUSED = []() {
  // Disable output buffering
  setbuf(stdout, nullptr);
  setbuf(stderr, nullptr);

  // Increase stack size
  struct rlimit stack_limit;
  stack_limit.rlim_cur = 1 << 20 /* 1 MiB */;
  stack_limit.rlim_max = stack_limit.rlim_cur;
  ABSL_RAW_CHECK(setrlimit(RLIMIT_STACK, &stack_limit) == 0, strerror(errno));

  // Initialize YARA. Note that the sandboxed code never calls yr_finalize().
  // Instead, the OS will clean up on process exit.
  const int err = yr_initialize();
  ABSL_RAW_CHECK(
      err == ERROR_SUCCESS,
      absl::StrCat("yr_initialize() failed with code: ", err).c_str());
  return true;
}();

// Global dispatch queue used to schedule new scan tasks
ABSL_CONST_INIT static absl::Mutex g_queue_mutex(absl::kConstInit);
static auto* g_queue GUARDED_BY(g_queue_mutex) = new std::queue<ScanTask>();

static uint64_t g_result_id GUARDED_BY(g_queue_mutex) = 0;

// This map tracks scan results. It relies on pointers staying stable, so this
// uses a node_hash_map<> instead of a flat_hash_map<>.
ABSL_CONST_INIT static absl::Mutex g_results_mutex(absl::kConstInit);
static auto* g_results GUARDED_BY(g_results_mutex) =
    new absl::node_hash_map<uint64_t, ScanResult>();

ABSL_CONST_INIT static absl::Mutex g_rules_mutex(absl::kConstInit);
static YR_RULES* g_rules GUARDED_BY(g_rules_mutex) = nullptr;

void ScanWorker()
{
  while (true)
  {
    // Wait for and retrieve a new ScanTask from the queue.
    g_queue_mutex.LockWhen(absl::Condition(
        +[](std::queue<ScanTask>* queue) { return !queue->empty(); }, g_queue));
    const ScanTask task = std::move(g_queue->front());
    g_queue->pop();
    g_queue_mutex.Unlock();

    ScanResult result;
    {
      absl::ReaderMutexLock lock(&g_rules_mutex);
      result.code = yr_rules_scan_fd(
          g_rules,
          task.data_fd,
          // Disable SIGSEGV handler, allowing YARA to crash/coredump.
          SCAN_FLAGS_NO_TRYCATCH,
          CollectMatches,
          /*user_data=*/reinterpret_cast<void*>(&result.matches),
          absl::ToInt64Seconds(task.timeout));
    }
    {
      absl::MutexLock lock(&g_results_mutex);
      (*g_results)[task.result_id] = std::move(result);
    }

    // Unblock any waiting clients on the host side. This should always succeed
    // writing 8 bytes, as long as the event_fd stays open in this function,
    // hence the CHECK.
    uint64_t unblock_value = 1;
    ABSL_RAW_CHECK(
        write(task.event_fd, &unblock_value, sizeof(unblock_value)) ==
            sizeof(unblock_value),
        strerror(errno));

    close(task.event_fd);
    close(task.data_fd);
  }
}

}  // namespace

extern "C" void YaraInitWorkers(int num_workers)
{
  const int num_threads = std::min(
      static_cast<unsigned int>(std::min(num_workers, YR_MAX_THREADS)),
      std::thread::hardware_concurrency());

  static auto* workers = new std::vector<std::thread>();
  workers->reserve(num_threads);

  for (int i = 0; i < num_threads; ++i)
  {
    workers->emplace_back(ScanWorker);
  }
}

// Initializes the global YARA rules set from a string. Returns the number of
// rules loaded. Extended error information can be found in status if it is not
// nullptr.
extern "C" int YaraLoadRules(const char* rule_string, YaraStatus* error_status)
{
  _YR_COMPILER* compiler;
  int error = yr_compiler_create(&compiler);

  if (error != ERROR_SUCCESS)
  {
    if (error_status)
    {
      error_status->set_code(error);
    }
    return 0;
  }

  std::unique_ptr<_YR_COMPILER, void (*)(_YR_COMPILER*)> compiler_cleanup(
      compiler, yr_compiler_destroy);

  if (yr_compiler_add_string(compiler, rule_string, nullptr) != 0)
  {
    if (error_status)
    {
      error_status->set_code(compiler->last_error);

      char message[512] = {'\0'};
      yr_compiler_get_error_message(compiler, message, sizeof(message));
      error_status->set_message(message);
    }
    return 0;
  }

  YR_RULES* rules = nullptr;
  error = yr_compiler_get_rules(compiler, &rules);

  if (error != ERROR_SUCCESS)
  {
    if (error_status)
    {
      error_status->set_code(error);
    }
    return 0;
  }

  int num_rules = 0;
  YR_RULE* rule;
  yr_rules_foreach(rules, rule) { ++num_rules; }

  absl::MutexLock lock(&g_rules_mutex);

  if (g_rules)
  {
    yr_rules_destroy(g_rules);
  }

  g_rules = rules;

  return num_rules;
}

// Schedules a new asynchronous YARA scan task on the data in the specified file
// descriptor. Notifies host code via writing to the event_fd file descriptor.
// Returns a unique identifier that can be used to retrieve the results.
extern "C" uint64_t YaraAsyncScanFd(int data_fd, int event_fd, int timeout_secs)
{
  absl::MutexLock queue_lock(&g_queue_mutex);
  ++g_result_id;
  g_queue->push({g_result_id, data_fd, event_fd, absl::Seconds(timeout_secs)});
  return g_result_id;
}

extern "C" int YaraGetScanResult(uint64_t result_id, YaraMatches* matches)
{
  absl::MutexLock lock(&g_results_mutex);
  auto result = g_results->find(result_id);

  if (result == g_results->end())
  {
    return -1;
  }

  int code = result->second.code;
  *matches = std::move(result->second.matches);
  g_results->erase(result);

  return code;
}

}  // namespace yara
