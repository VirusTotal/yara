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

# Bazel (http://bazel.io/) BUILD file for the libmagic library.

# Rule for creating magic.h from magic.h.in. The two files are identical, except
# for magic.h.in not having the actual version number. Instead it has a X.YY
# placeholder that is replaced with the version number (i.e: 545) during build
# time. When this library is updated the version number in this rule must be
# updated accordingly.
genrule(
    name = "magic_h",
    srcs = ["src/magic.h.in"],
    outs = ["src/magic.h"],
    cmd = """
        sed -e 's/X.YY/545/' < $(location src/magic.h.in) > $(location src/magic.h)
    """,
)

MAGIC_COPTS = [
    # The VERSION macro usually contains the actual version (e.g: "5.38") but
    # any arbitrary string will work. We simply use "BUILT_BY_YARA".
    "-DVERSION=\\\"BUILT_BY_YARA\\\"",
] + select({
    "@bazel_tools//src/conditions:darwin": [
        "-DHAVE_FORK=1",
        "-DHAVE_INTTYPES_H=1",
        "-DHAVE_STDINT_H=1",
        "-DHAVE_STRLCAT=1",
        "-DHAVE_STRLCPY=1",
        "-DHAVE_UNISTD_H=1",
    ],
    "@bazel_tools//src/conditions:freebsd": [
        "-DHAVE_FORK=1",
        "-DHAVE_INTTYPES_H=1",
        "-DHAVE_STDINT_H=1",
        "-DHAVE_STRLCAT=1",
        "-DHAVE_STRLCPY=1",
        "-DHAVE_UNISTD_H=1",
    ],
    "@bazel_tools//src/conditions:linux_aarch64": [
        "-DHAVE_FORK=1",
        "-DHAVE_INTTYPES_H=1",
        "-DHAVE_STDINT_H=1",
        "-DHAVE_UNISTD_H=1",
    ],
    "@bazel_tools//src/conditions:linux_x86_64": [
        "-DHAVE_FORK=1",
        "-DHAVE_INTTYPES_H=1",
        "-DHAVE_STDINT_H=1",
        "-DHAVE_UNISTD_H=1",
        "-DHAVE_MKSTEMP=1",
    ],
    "@bazel_tools//src/conditions:windows": [
    ],
})

cc_library(
    name = "magic",
    srcs = glob(["src/*.h"]) + [
        "src/apprentice.c",
        "src/apptype.c",
        "src/ascmagic.c",
        "src/asctime_r.c",
        "src/asprintf.c",
        "src/buffer.c",
        "src/cdf.c",
        "src/cdf_time.c",
        "src/compress.c",
        "src/ctime_r.c",
        "src/der.c",
        "src/dprintf.c",
        "src/encoding.c",
        "src/fmtcheck.c",
        "src/fsmagic.c",
        "src/funcs.c",
        "src/getline.c",
        "src/getopt_long.c",
        "src/gmtime_r.c",
        "src/is_csv.c",
        "src/is_json.c",
        "src/is_simh.c",
        "src/is_tar.c",
        "src/localtime_r.c",
        "src/magic.c",
        "src/pread.c",
        "src/print.c",
        "src/readcdf.c",
        "src/readelf.c",
        "src/seccomp.c",
        "src/softmagic.c",
        "src/strcasestr.c",
        "src/vasprintf.c",
    ] + select({
        "@bazel_tools//src/conditions:darwin": [
        ],
        "@bazel_tools//src/conditions:freebsd": [
        ],
        "@bazel_tools//src/conditions:linux_aarch64": [
            "src/strlcat.c",
            "src/strlcpy.c",
        ],
        "@bazel_tools//src/conditions:linux_x86_64": [
            "src/strlcat.c",
            "src/strlcpy.c",
        ],
        "@bazel_tools//src/conditions:windows": [
            "src/strlcat.c",
            "src/strlcpy.c",
        ],
    }),
    hdrs = ["src/magic.h"],
    copts = MAGIC_COPTS,
    includes = [
        ".",
        "src",
    ],
    visibility = ["//visibility:public"],
)
