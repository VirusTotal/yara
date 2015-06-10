package com.github.plusvic.yara;


import org.fusesource.hawtjni.runtime.*;

/**
 * Yara JNI library
 */
@JniClass
public class YaraLibrary {
    private Library library;

    public YaraLibrary() {
        library = new Library("yara-wrapper", YaraLibrary.class);
        library.load();
    }

    /*
        Yara functions
     */
    final native int yr_initialize();
    final native int yr_finalize();

    /*
        Compilation
     */
    final native int yr_compiler_create(@JniArg(cast="YR_COMPILER **") long[] compilerRef);
    final native void yr_compiler_destroy(@JniArg(cast="YR_COMPILER *") long compiler);
    final native void yr_compiler_set_callback(
            @JniArg(cast="YR_COMPILER*") long compiler,
            @JniArg(cast="void (*)(int, const char*, int, const char*,void*)", flags = ArgFlag.POINTER_ARG)long callback,
            @JniArg(cast="void *")long data
    );
    final native int yr_compiler_add_string(
            @JniArg(cast="YR_COMPILER *")long compiler,
            String rules,
            String namespace);
    final native int yr_compiler_get_rules(
            @JniArg(cast="YR_COMPILER*")long compiler,
            @JniArg(cast="YR_RULES**")long[] rules);
    final native int yr_rules_destroy(@JniArg(cast="YR_RULES*")long rules);


    @JniMethod
    final native int yr_rules_scan_file(
            @JniArg(cast="YR_RULES*")long rules,
            String filename,
            int flags,
            @JniArg(cast="YR_CALLBACK_FUNC")long callback,
            @JniArg(cast="void*")long  user_data,
            int timeout);

    /*
        Mapping helpers
     */
    final native String cast_jstring(JNIEnv  env,@JniArg(cast = "const char*")long pv);

    /*
        Rules
     */
    final native String yara_rule_identifier(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native long   yara_rule_metas(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native long   yara_rule_meta_next(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native long   yara_rule_strings(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native long   yara_rule_string_next(JNIEnv env, @JniArg(cast = "void*")long pv);

    /*
        Metas
    */
    final native int    yara_meta_type(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native String yara_meta_identifier(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native String yara_meta_string(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native int    yara_meta_integer(JNIEnv env, @JniArg(cast = "void*")long pv);

    /*
        Strings
     */
    final native String yara_string_identifier(JNIEnv env,@JniArg(cast = "void*") long pv);
    final native long   yara_string_matches(JNIEnv env,@JniArg(cast = "void*") long pv);
    final native long   yara_string_match_next(JNIEnv env,@JniArg(cast = "void*") long pv);

    /*
        Matches
     */
    final native long   yara_match_offset(JNIEnv env, @JniArg(cast = "void*")long pv);
    final native String yara_match_value(JNIEnv env, @JniArg(cast = "void*")long pv);
}
