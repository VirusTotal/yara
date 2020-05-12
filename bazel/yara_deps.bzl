# Copyright (c) 2020. The YARA Authors. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation and/or
# other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
# ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
# ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""Load dependencies needed to compile YARA as a 3rd-party consumer."""


load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")


def yara_deps():
    """Loads common dependencies needed to compile YARA."""
    maybe(
        http_archive,
        name = "openssl",
        url = "https://github.com/openssl/openssl/archive/OpenSSL_1_1_0h.tar.gz",
        sha256 = "f56dd7d81ce8d3e395f83285bd700a1098ed5a4cb0a81ce9522e41e6db7e0389",
        strip_prefix = "openssl-OpenSSL_1_1_0h",
        build_file = "@com_github_virustotal_yara//:bazel/openssl.BUILD",
    )
    maybe(
        git_repository,
        name = "boringssl",
        commit = "095d78b14f91cc9a910408eaae84a3bdafc54da9",  # 2019-06-05
        remote = "https://boringssl.googlesource.com/boringssl",
        shallow_since = "1559759280 +0000",
    )
    maybe(
        http_archive,
        name = "jansson",
        url = "https://github.com/akheron/jansson/archive/v2.12.tar.gz",
        sha256 = "76260d30e9bbd0ef392798525e8cd7fe59a6450c54ca6135672e3cd6a1642941",
        strip_prefix = "jansson-2.12",
        build_file = "@com_github_virustotal_yara//:bazel/jansson.BUILD",
    )
    maybe(
        # When updating this dependency to a more recent version, the version
        # in the bazel/magic.BUILD must be updated acordingly.
        http_archive,
        name = "magic",
        url = "https://github.com/file/file/archive/FILE5_38.tar.gz",
        sha256 = "338ebe8cb536a3f86750b4df62be2d382f6da66afdb0087b36a1a3e14ea4baf8",
        strip_prefix = "file-FILE5_38",
        build_file = "@com_github_virustotal_yara//:bazel/magic.BUILD",
    )
    maybe(
        git_repository,
        name = "com_google_sandboxed_api",
        commit = "144a441d798f13d27cc71e7c2a630e0063d747b5",  # 2020-05-12
        remote = "https://github.com/google/sandboxed-api.git",
        shallow_since = "1589270865 -0700",
    )
    maybe(
        http_archive,
        name = "rules_proto",
        sha256 = "602e7161d9195e50246177e7c55b2f39950a9cf7366f74ed5f22fd45750cd208",
        strip_prefix = "rules_proto-97d8af4dc474595af3900dd85cb3a29ad28cc313",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
            "https://github.com/bazelbuild/rules_proto/archive/97d8af4dc474595af3900dd85cb3a29ad28cc313.tar.gz",
        ],
    )
    maybe(
        # GoogleTest/GoogleMock for testing the sandbox
        http_archive,
        name = "com_google_googletest",
        sha256 = "ba5b04a4849246e7c16ba94227eed46486ef942f61dc8b78609732543c19c9f4",  # 2019-11-21
        strip_prefix = "googletest-200ff599496e20f4e39566feeaf2f6734ca7570f",
        urls = ["https://github.com/google/googletest/archive/200ff599496e20f4e39566feeaf2f6734ca7570f.zip"],
    )
