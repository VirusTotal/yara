"""Load dependencies needed to compile YARA as a 3rd-party consumer."""
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def yara_deps():
    """Loads common dependencies needed to compile YARA."""
    if not native.existing_rule("openssl"):
        http_archive(
            name = "openssl",
            url = "https://github.com/openssl/openssl/archive/OpenSSL_1_1_0h.tar.gz",
            sha256 = "f56dd7d81ce8d3e395f83285bd700a1098ed5a4cb0a81ce9522e41e6db7e0389",
            strip_prefix = "openssl-OpenSSL_1_1_0h",
            build_file = "@//:bazel/openssl.BUILD",
        )
