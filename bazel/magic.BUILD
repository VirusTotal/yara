
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

genrule(
    name = "magic_h",
    srcs = ["src/magic.h.in"],
    outs = ["src/magic.h"],
    cmd = """
        sed -e 's/X.YY/538/' < $(location src/magic.h.in) > $(location src/magic.h)
    """,
)

cc_library(
    name = "magic",
    hdrs = glob(["src/*.h"]) + ["src/magic.h"],
    srcs = [
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
        #"src/file.c",
        "src/fmtcheck.c",
        "src/fsmagic.c",
        "src/funcs.c",
        "src/getline.c",
        "src/getopt_long.c",
        "src/gmtime_r.c",
        "src/is_csv.c",
        "src/is_json.c",
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
        #"src/strlcat.c",
        #"src/strlcpy.c",
        "src/teststrchr.c",
        "src/vasprintf.c",
    ],
    includes = [".", "src"],
    defines = [
        "VERSION=\\\"5.38\\\"",
        "HAVE_FORK=1",
        "HAVE_STDINT_H=1",
        "HAVE_STRLCPY=1",
        "HAVE_STRLCAT=1",
        "HAVE_INTTYPES_H=1",
        "HAVE_UNISTD_H=1",
    ],
    copts = [],
    visibility = ["//visibility:public"],
)
