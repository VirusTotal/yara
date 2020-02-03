# Copyright (c) 2019. The YARA Authors. All Rights Reserved.
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

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

# BoringSSL, see
# https://boringssl.googlesource.com/boringssl/+/master/INCORPORATING.md#bazel
git_repository(
    name = "boringssl",
    commit = "095d78b14f91cc9a910408eaae84a3bdafc54da9",  # 2019-06-05
    remote = "https://boringssl.googlesource.com/boringssl",
    shallow_since = "1559759280 +0000",
)

# OpenSSL
http_archive(
    name = "openssl",
    url = "https://github.com/openssl/openssl/archive/OpenSSL_1_1_0h.tar.gz",
    sha256 = "f56dd7d81ce8d3e395f83285bd700a1098ed5a4cb0a81ce9522e41e6db7e0389",
    strip_prefix = "openssl-OpenSSL_1_1_0h",
    build_file = "@//:openssl.BUILD",
)

# Sandboxed API
git_repository(
    name = "com_google_sandboxed_api",
    commit = "2301e05097818734f59b881d7fbe1624c17fc840",  # 2019-07-08
    remote = "https://github.com/google/sandboxed-api.git",
    shallow_since = "1562590596 -0700",
)

load(
    "@com_google_sandboxed_api//sandboxed_api/bazel:sapi_deps.bzl",
    "sapi_deps",
)

sapi_deps()

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

# GoogleTest/GoogleMock for testing the sandbox
http_archive(
    name = "com_google_googletest",
    sha256 = "baed63b97595c32667694de0a434f8f23da59609c4a44f3360ba94b0abd5c583",
    strip_prefix = "googletest-8ffb7e5c88b20a297a2e786c480556467496463b",
    urls = ["https://github.com/google/googletest/archive/8ffb7e5c88b20a297a2e786c480556467496463b.zip"],  # 2019-05-30
)
