YARA_CONFIG_OPTS = [
    "-DHAVE_CLOCK_GETTIME=1",
    #"-DHAVE_COMMONCRYPTO_COMMONCRYPTO_H",
    "-DHAVE_LIBCRYPTO=1",
    "-DHAVE_MEMMEM=1",
    "-DHAVE_STDBOOL_H=1",
    # "-DHAVE__MKGMTIME=1",
    "-DHAVE_TIMEGM=1",
]

YARA_COPTS = YARA_CONFIG_OPTS + [
    "-D_GNU_SOURCE",
    # Tell the compiler we want the C99 standard.
    "-std=c99",
    # Additional include paths.
    "-Ilibyara",
    "-Ilibyara/modules",
] + select({
    "@bazel_tools//src/conditions:darwin": [
        "-DUSE_MACH_PROC",
        "-DHAVE_SCAN_PROC_IMPL=1",
        "-DHAVE_STRLCAT=1",
        "-DHAVE_STRLCPY=1",
    ],
    "@bazel_tools//src/conditions:freebsd": [
        "-DUSE_FREEBSD_PROC",
        "-DHAVE_SCAN_PROC_IMPL=1",
        "-DHAVE_STRLCAT=1",
        "-DHAVE_STRLCPY=1",
    ],
    "@bazel_tools//src/conditions:linux_aarch64": [
        "-DUSE_LINUX_PROC",
        "-DHAVE_SCAN_PROC_IMPL=1",
    ],
    "@bazel_tools//src/conditions:linux_x86_64": [
        "-DUSE_LINUX_PROC",
        "-DHAVE_SCAN_PROC_IMPL=1",
    ],
    "@bazel_tools//src/conditions:windows": [
        "-DUSE_WINDOWS_PROC",
        "-DHAVE_SCAN_PROC_IMPL=1",
    ],
    "//conditions:default": ["-DUSE_NO_PROC"],
})

# Define rule for generating the module_list file. This rule has an attribute
# "modules" which is a list of module names that we want in the file.
def _module_list_impl(ctx):
    output = ctx.outputs.out
    content = "\n".join(["MODULE(%s)" % m for m in ctx.attr.modules])
    ctx.actions.write(output = output, content = content)

module_list = rule(
    implementation = _module_list_impl,
    attrs = {"modules": attr.string_list()},
    outputs = {"out": "libyara/modules/module_list"},
)

def yara_library(
        name,
        defines = [],
        modules = [],
        modules_srcs = [],
        deps = [],
        copts = YARA_COPTS,
        crypto_libs = ["@openssl//:crypto"]):
    """Macro for generating the YARA library with a specific list of modules.

    This macro allows to cherry-pick the modules that you want to build into the
    library. For example, for building it with modules pe and elf only, you can
    use:

    yara_library(
      name = "libyara",
      modules = [
          "cuckoo",
          "dex",
          "dotnet",
          "elf",
      ],
      modules_srcs = [
          "libyara/modules/elf/elf.c",
          "libyara/modules/pe/pe.c",
          "libyara/modules/pe/pe_utils.c",
      ]
    )

    The "modules_srcs" list must contain the source files implementing the modules
    listed in the "modules" argument.
    """
    module_list(
        name = "module_list",
        modules = modules,
    )

    native.cc_library(
        name = name,
        defines = defines + [m.upper() + "_MODULE" for m in modules],
        srcs = modules_srcs + [
            "libyara/ahocorasick.c",
            "libyara/arena.c",
            "libyara/atoms.c",
            "libyara/base64.c",
            "libyara/bitmask.c",
            "libyara/compiler.c",
            "libyara/crypto.h",
            "libyara/endian.c",
            "libyara/exception.h",
            "libyara/exec.c",
            "libyara/exefiles.c",
            "libyara/filemap.c",
            "libyara/grammar.c",
            "libyara/hash.c",
            "libyara/hex_grammar.c",
            "libyara/hex_grammar.h",
            "libyara/hex_lexer.c",
            "libyara/include/yara.h",
            "libyara/include/yara/ahocorasick.h",
            "libyara/include/yara/arena.h",
            "libyara/include/yara/atoms.h",
            "libyara/include/yara/base64.h",
            "libyara/include/yara/bitmask.h",
            "libyara/include/yara/compiler.h",
            "libyara/include/yara/dex.h",
            "libyara/include/yara/dotnet.h",
            "libyara/include/yara/elf.h",
            "libyara/include/yara/endian.h",
            "libyara/include/yara/error.h",
            "libyara/include/yara/exec.h",
            "libyara/include/yara/exefiles.h",
            "libyara/include/yara/filemap.h",
            "libyara/include/yara/globals.h",
            "libyara/include/yara/hash.h",
            "libyara/include/yara/hex_lexer.h",
            "libyara/include/yara/integers.h",
            "libyara/include/yara/lexer.h",
            "libyara/include/yara/libyara.h",
            "libyara/include/yara/limits.h",
            "libyara/include/yara/macho.h",
            "libyara/include/yara/mem.h",
            "libyara/include/yara/modules.h",
            "libyara/include/yara/notebook.h",
            "libyara/include/yara/object.h",
            "libyara/include/yara/parser.h",
            "libyara/include/yara/pe.h",
            "libyara/include/yara/pe_utils.h",
            "libyara/include/yara/proc.h",
            "libyara/include/yara/re.h",
            "libyara/include/yara/re_lexer.h",
            "libyara/include/yara/rules.h",
            "libyara/include/yara/scan.h",
            "libyara/include/yara/scanner.h",
            "libyara/include/yara/sizedstr.h",
            "libyara/include/yara/stack.h",
            "libyara/include/yara/stopwatch.h",
            "libyara/include/yara/stream.h",
            "libyara/include/yara/strutils.h",
            "libyara/include/yara/threading.h",
            "libyara/include/yara/types.h",
            "libyara/include/yara/utils.h",
            "libyara/lexer.c",
            "libyara/libyara.c",
            "libyara/mem.c",
            "libyara/modules.c",
            "libyara/notebook.c",
            "libyara/object.c",
            "libyara/parser.c",
            "libyara/proc.c",
            "libyara/proc/freebsd.c",
            "libyara/proc/linux.c",
            "libyara/proc/mach.c",
            "libyara/proc/none.c",
            "libyara/proc/openbsd.c",
            "libyara/proc/windows.c",
            "libyara/re.c",
            "libyara/re_grammar.c",
            "libyara/re_grammar.h",
            "libyara/re_lexer.c",
            "libyara/rules.c",
            "libyara/scan.c",
            "libyara/scanner.c",
            "libyara/sizedstr.c",
            "libyara/stack.c",
            "libyara/stopwatch.c",
            "libyara/stream.c",
            "libyara/strutils.c",
            "libyara/threading.c",
        ],
        hdrs = [
            "libyara/include/yara.h",
            "libyara/include/yara/pe.h",
            "libyara/include/yara/proc.h",
            "libyara/include/yara/rules.h",
        ],
        copts = copts,
        includes = [
            "libyara/modules",
            "libyara/include",
            "libyara",
        ],
        textual_hdrs = [
            ":module_list",
            "libyara/grammar.h",
            "libyara/hex_grammar.y",
            "libyara/re_grammar.y",
        ],
        deps = deps + crypto_libs,
        visibility = ["//visibility:public"],
    )
