config_setting(
    name = "darwin",
    values = {
        "cpu": "darwin_x86_64",
    },
)

cc_library(
    name = "crypto",
    hdrs = glob(["include/openssl/*.h"]) + ["include/openssl/opensslconf.h"],
    srcs = ["libcrypto.a"],
    includes = ["include"],
    linkopts = select({
        ":darwin": [],
        "//conditions:default": ["-lpthread", "-ldl"],
    }),
    visibility = ["//visibility:public"],
)

cc_library(
    name = "ssl",
    deps = [":crypto"],
    hdrs = glob(["include/openssl/*.h"]) + ["include/openssl/opensslconf.h"],
    srcs = ["libssl.a"],
    includes = ["include"],
    visibility = ["//visibility:public"],
)

genrule(
    name = "openssl-build",
    srcs = glob(["**/*"], exclude=["bazel-*"]),
    outs = [
        "libcrypto.a",
        "libssl.a",
        "include/openssl/opensslconf.h",
    ],
    cmd = """
        OPENSSL_ROOT=$$(dirname $(location config))
        pushd $$OPENSSL_ROOT
            ./config
            make -j 8
        popd
        cp $$OPENSSL_ROOT/libcrypto.a $(location libcrypto.a)
        cp $$OPENSSL_ROOT/libssl.a $(location libssl.a)
        cp $$OPENSSL_ROOT/include/openssl/opensslconf.h $(location include/openssl/opensslconf.h)
    """,
)
