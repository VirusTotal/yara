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

#include <fcntl.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <memory>
#include <sstream>

#include "sandbox/yara_transaction.h"
#include "sandboxed_api/util/statusor.h"
// TODO(cblichmann): SAPI leaks these symbols currently.
#undef ABSL_FLAG
#undef ABSL_DECLARE_FLAG
#undef ABSL_RETIRED_FLAG

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"

ABSL_FLAG(std::string, identifier, "", "print only rules with this name");
ABSL_FLAG(int, timeout, 5, "abort scanning after the given number of seconds");

namespace yara {
namespace {

::sapi::StatusOr<std::string> ReadFileToString(absl::string_view filename) {
  std::ifstream input(std::string(filename), std::ios::in | std::ios::binary);
  std::ostringstream output;
  output << input.rdbuf();
  if (!input) {
    return absl::UnknownError(absl::StrCat("Cannot read file '", filename, "'"));
  }
  return output.str();
}

}  // namespace

// Implements a subset of the YARA command line scanner, but runs the actual
// scan inside of a sandbox.
absl::Status YaraMain(const std::vector<char*>& args) {
  if (args.size() < 3) {
    return absl::InvalidArgumentError("Missing operand. Try '--help'.");
  }

  // Get file to scan and concatenate all the YARA rules from the specified
  // files.
  std::string scan_filename = args.back();
  std::string all_rules;
  for (size_t i = 1; i != args.size() - 1; ++i) {
    SAPI_ASSIGN_OR_RETURN(std::string rules, ReadFileToString(args[i]));
    absl::StrAppend(&all_rules, rules, "\n");
  }

  SAPI_ASSIGN_OR_RETURN(
      auto transaction,
      YaraTransaction::Create(
          YaraTransaction::Options()
              .set_scan_timeout(absl::Seconds(absl::GetFlag(FLAGS_timeout)))
              .set_num_workers(1)));
  SAPI_ASSIGN_OR_RETURN(int num_rules ABSL_ATTRIBUTE_UNUSED,
                        transaction->LoadRules(all_rules));

  struct FDCloser {
    ~FDCloser() { close(fd); }
    int fd;
  } fd_closer{open(scan_filename.c_str(), O_RDONLY)};
  if (fd_closer.fd == -1) {
    return absl::UnknownError(absl::StrCat(
        "Cannot open file '", scan_filename, "': ", strerror(errno)));
  }

  SAPI_ASSIGN_OR_RETURN(YaraMatches matches, transaction->ScanFd(fd_closer.fd));
  for (const auto& match : matches.match()) {
    const std::string& rule_name = match.id().rule_name();
    if (absl::GetFlag(FLAGS_identifier).empty() ||
        (absl::GetFlag(FLAGS_identifier) == rule_name)) {
      absl::PrintF("%s %s\n", rule_name, scan_filename);
    }
  }

  return absl::OkStatus();
}

}  // namespace yara

int main(int argc, char* argv[]) {
  absl::string_view argv0 = argv[0];
  {
    auto last_slash_pos = argv0.find_last_of("/\\");
    if (last_slash_pos != absl::string_view::npos) {
      argv0 = argv0.substr(last_slash_pos + 1);
    }
  }
  absl::SetProgramUsageMessage(
      absl::StrCat("YARA, the pattern matching swiss army knife.\n",
                   "Usage: ", argv0, " [OPTION] RULES_FILE... FILE"));

  absl::Status status = ::yara::YaraMain(absl::ParseCommandLine(argc, argv));
  if (!status.ok()) {
    absl::FPrintF(stderr, "ERROR: %s\n", status.message());
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}
