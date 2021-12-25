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

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "absl/strings/str_cat.h"
#include "libyara/include/yara/error.h"
#include "sandboxed_api/util/status_macros.h"

namespace yara
{
absl::Mutex YaraTransaction::mutex_(absl::kConstInit);

::sapi::StatusOr<std::unique_ptr<YaraTransaction>> YaraTransaction::Create(
    Options options)
{
  auto transaction = absl::WrapUnique(
      new YaraTransaction(options.scan_timeout));
  // "Run" the transaction in order to initialize the underlying sandbox.
  SAPI_RETURN_IF_ERROR(transaction->Run());

  sandbox::YaraApi api(transaction->sandbox());
  SAPI_RETURN_IF_ERROR(
      api.YaraInitWorkers(options.num_workers >= 1 ? options.num_workers : 1));

  return transaction;
}

::sapi::StatusOr<int> YaraTransaction::LoadRules(const std::string& rule_string)
{
  absl::MutexLock lock(&mutex_);
  sandbox::YaraApi api(sandbox());

  ::sapi::v::ConstCStr rule_string_sapi(rule_string.c_str());
  YaraStatus error_status;
  ::sapi::v::Proto<YaraStatus> error_status_sapi(error_status);
  SAPI_ASSIGN_OR_RETURN(
      int num_rules,
      api.YaraLoadRules(
          rule_string_sapi.PtrBefore(), error_status_sapi.PtrBoth()));
  if (num_rules <= 0)
  {
    auto error_status_copy = error_status_sapi.GetProtoCopy();
    if (!error_status_copy)
    {
      return absl::UnknownError("Deserialization of response failed");
    }
    return absl::InvalidArgumentError(error_status_copy->message());
  }
  return num_rules;
}

::sapi::StatusOr<YaraMatches> YaraTransaction::ScanFd(int fd)
{
  int local_event_fd = eventfd(0 /* initval */, 0 /* flags */);
  if (local_event_fd == -1)
  {
    return absl::InternalError(
        absl::StrCat("eventfd() error: ", strerror(errno)));
  }
  struct FDCloser
  {
    ~FDCloser() { close(event_fd); }
    int event_fd;
  } event_fd_closer = {local_event_fd};

  sandbox::YaraApi api(sandbox());
  uint64_t result_id;
  {
    absl::MutexLock lock(&mutex_);

    // Note: These SAPI Fd objects use the underlying sandbox comms to
    //       synchronize. Hence they must live within this locked scope.
    ::sapi::v::Fd event_fd(local_event_fd);
    SAPI_RETURN_IF_ERROR(sandbox()->TransferToSandboxee(&event_fd));
    event_fd.OwnLocalFd(false);   // Needs to be valid during poll()
    event_fd.OwnRemoteFd(false);  // Sandboxee will close

    ::sapi::v::Fd data_fd(fd);
    SAPI_RETURN_IF_ERROR(sandbox()->TransferToSandboxee(&data_fd));
    data_fd.OwnLocalFd(false);   // To be closed by caller
    data_fd.OwnRemoteFd(false);  // Sandboxee will close

    SAPI_ASSIGN_OR_RETURN(
        result_id,
        api.YaraAsyncScanFd(
            data_fd.GetRemoteFd(),
            event_fd.GetRemoteFd(),
            absl::ToInt64Seconds(scan_timeout_)));
  }

  pollfd poll_events{local_event_fd, POLLIN};
  int poll_result;

  // TEMP_FAILURE_RETRY is a GNU extension that retries if the call returns
  // EINTR.
  poll_result = TEMP_FAILURE_RETRY(poll(
      &poll_events,
      1 /* nfds */,
      // Add extra time to allow code inside the sandbox to time out first.
      absl::ToInt64Milliseconds(scan_timeout_ + absl::Seconds(10))));
  if (poll_result == 0)
  {
    return absl::DeadlineExceededError("Scan timeout during poll()");
  }

  if (poll_result == -1)
  {
    return absl::InternalError(absl::StrCat("poll() error: ", strerror(errno)));
  }
  if (poll_events.revents & POLLHUP || poll_events.revents & POLLERR ||
      poll_events.revents & POLLNVAL)
  {
    return absl::InternalError(
        absl::StrCat("poll() error, revents: ", poll_events.revents));
  }

  absl::MutexLock lock(&mutex_);
  YaraMatches matches;
  ::sapi::v::Proto<YaraMatches> matches_sapi(matches);
  SAPI_ASSIGN_OR_RETURN(
      int scan_result,
      api.YaraGetScanResult(result_id, matches_sapi.PtrBoth()));
  switch (scan_result)
  {
  case ERROR_SUCCESS:
  case ERROR_TOO_MANY_MATCHES:
  {
    auto matches_copy = matches_sapi.GetProtoCopy();
    if (!matches_copy)
    {
      return absl::UnknownError("Deserialization of response failed");
    }
    return *matches_copy;
  }

  case ERROR_SCAN_TIMEOUT:
    return absl::DeadlineExceededError("Scan timeout");
  }
  return absl::InternalError(absl::StrCat("Error during scan: ", scan_result));
}

}  // namespace yara
