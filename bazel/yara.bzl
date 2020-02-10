
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
    content = '\n'.join(["MODULE(%s)" % m for m in ctx.attr.modules])
    ctx.actions.write(output = output, content = content)

module_list = rule(
    implementation = _module_list_impl,
    attrs = {"modules": attr.string_list()},
    outputs = {"out": "libyara/modules/module_list"},
)


def yara_library(name, defines=[], modules=[], modules_srcs=[],
                 crypto_libs=["@openssl//:crypto"]):
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
        "@com_github_virustotal_yara//:libyara/ahocorasick.c",
        "@com_github_virustotal_yara//:libyara/arena.c",
        "@com_github_virustotal_yara//:libyara/atoms.c",
        "@com_github_virustotal_yara//:libyara/bitmask.c",
        "@com_github_virustotal_yara//:libyara/compiler.c",
        "@com_github_virustotal_yara//:libyara/crypto.h",
        "@com_github_virustotal_yara//:libyara/endian.c",
        "@com_github_virustotal_yara//:libyara/exception.h",
        "@com_github_virustotal_yara//:libyara/exec.c",
        "@com_github_virustotal_yara//:libyara/exefiles.c",
        "@com_github_virustotal_yara//:libyara/filemap.c",
        "@com_github_virustotal_yara//:libyara/grammar.c",
        "@com_github_virustotal_yara//:libyara/hash.c",
        "@com_github_virustotal_yara//:libyara/hex_grammar.c",
        "@com_github_virustotal_yara//:libyara/hex_grammar.h",
        "@com_github_virustotal_yara//:libyara/hex_lexer.c",
        "@com_github_virustotal_yara//:libyara/include/yara.h",
        "@com_github_virustotal_yara//:libyara/include/yara/ahocorasick.h",
        "@com_github_virustotal_yara//:libyara/include/yara/arena.h",
        "@com_github_virustotal_yara//:libyara/include/yara/atoms.h",
        "@com_github_virustotal_yara//:libyara/include/yara/bitmask.h",
        "@com_github_virustotal_yara//:libyara/include/yara/compiler.h",
        "@com_github_virustotal_yara//:libyara/include/yara/dex.h",
        "@com_github_virustotal_yara//:libyara/include/yara/dotnet.h",
        "@com_github_virustotal_yara//:libyara/include/yara/elf.h",
        "@com_github_virustotal_yara//:libyara/include/yara/endian.h",
        "@com_github_virustotal_yara//:libyara/include/yara/error.h",
        "@com_github_virustotal_yara//:libyara/include/yara/exec.h",
        "@com_github_virustotal_yara//:libyara/include/yara/exefiles.h",
        "@com_github_virustotal_yara//:libyara/include/yara/filemap.h",
        "@com_github_virustotal_yara//:libyara/include/yara/globals.h",
        "@com_github_virustotal_yara//:libyara/include/yara/hash.h",
        "@com_github_virustotal_yara//:libyara/include/yara/hex_lexer.h",
        "@com_github_virustotal_yara//:libyara/include/yara/integers.h",
        "@com_github_virustotal_yara//:libyara/include/yara/lexer.h",
        "@com_github_virustotal_yara//:libyara/include/yara/libyara.h",
        "@com_github_virustotal_yara//:libyara/include/yara/limits.h",
        "@com_github_virustotal_yara//:libyara/include/yara/macho.h",
        "@com_github_virustotal_yara//:libyara/include/yara/mem.h",
        "@com_github_virustotal_yara//:libyara/include/yara/modules.h",
        "@com_github_virustotal_yara//:libyara/include/yara/object.h",
        "@com_github_virustotal_yara//:libyara/include/yara/parser.h",
        "@com_github_virustotal_yara//:libyara/include/yara/pe.h",
        "@com_github_virustotal_yara//:libyara/include/yara/pe_utils.h",
        "@com_github_virustotal_yara//:libyara/include/yara/proc.h",
        "@com_github_virustotal_yara//:libyara/include/yara/re.h",
        "@com_github_virustotal_yara//:libyara/include/yara/re_lexer.h",
        "@com_github_virustotal_yara//:libyara/include/yara/rules.h",
        "@com_github_virustotal_yara//:libyara/include/yara/scan.h",
        "@com_github_virustotal_yara//:libyara/include/yara/scanner.h",
        "@com_github_virustotal_yara//:libyara/include/yara/sizedstr.h",
        "@com_github_virustotal_yara//:libyara/include/yara/stack.h",
        "@com_github_virustotal_yara//:libyara/include/yara/stopwatch.h",
        "@com_github_virustotal_yara//:libyara/include/yara/stream.h",
        "@com_github_virustotal_yara//:libyara/include/yara/strutils.h",
        "@com_github_virustotal_yara//:libyara/include/yara/threading.h",
        "@com_github_virustotal_yara//:libyara/include/yara/types.h",
        "@com_github_virustotal_yara//:libyara/include/yara/utils.h",
        "@com_github_virustotal_yara//:libyara/lexer.c",
        "@com_github_virustotal_yara//:libyara/libyara.c",
        "@com_github_virustotal_yara//:libyara/mem.c",
        "@com_github_virustotal_yara//:libyara/modules.c",
        "@com_github_virustotal_yara//:libyara/object.c",
        "@com_github_virustotal_yara//:libyara/parser.c",
        "@com_github_virustotal_yara//:libyara/proc.c",
        "@com_github_virustotal_yara//:libyara/proc/freebsd.c",
        "@com_github_virustotal_yara//:libyara/proc/linux.c",
        "@com_github_virustotal_yara//:libyara/proc/mach.c",
        "@com_github_virustotal_yara//:libyara/proc/none.c",
        "@com_github_virustotal_yara//:libyara/proc/openbsd.c",
        "@com_github_virustotal_yara//:libyara/proc/windows.c",
        "@com_github_virustotal_yara//:libyara/re.c",
        "@com_github_virustotal_yara//:libyara/re_grammar.c",
        "@com_github_virustotal_yara//:libyara/re_grammar.h",
        "@com_github_virustotal_yara//:libyara/re_lexer.c",
        "@com_github_virustotal_yara//:libyara/rules.c",
        "@com_github_virustotal_yara//:libyara/scan.c",
        "@com_github_virustotal_yara//:libyara/scanner.c",
        "@com_github_virustotal_yara//:libyara/sizedstr.c",
        "@com_github_virustotal_yara//:libyara/stack.c",
        "@com_github_virustotal_yara//:libyara/stopwatch.c",
        "@com_github_virustotal_yara//:libyara/stream.c",
        "@com_github_virustotal_yara//:libyara/strutils.c",
        "@com_github_virustotal_yara//:libyara/threading.c",
    ],
    hdrs = [
        "@com_github_virustotal_yara//:libyara/include/yara.h",
        "@com_github_virustotal_yara//:libyara/include/yara/pe.h",
        "@com_github_virustotal_yara//:libyara/include/yara/proc.h",
        "@com_github_virustotal_yara//:libyara/include/yara/rules.h",
    ],
    copts = YARA_COPTS,
    includes = [
        "ibyara/modules",
        "libyara/include",
        "libyara",
    ],
    textual_hdrs = [
        "@com_github_virustotal_yara//:module_list",
        "@com_github_virustotal_yara//:libyara/grammar.h",
        "@com_github_virustotal_yara//:libyara/hex_grammar.y",
        "@com_github_virustotal_yara//:libyara/re_grammar.y",

    ],
    deps = crypto_libs + [
        "@jansson//:jansson",
    ],
    visibility = ["//visibility:public"],
  )
