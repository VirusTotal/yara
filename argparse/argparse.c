#include "argparse.h"

#define OPT_UNSET 1

static const char *
prefix_skip(const char *str, const char *prefix)
{
    size_t len = strlen(prefix);
    return strncmp(str, prefix, len) ? NULL : str + len;
}

int
prefix_cmp(const char *str, const char *prefix)
{
    for (;; str++, prefix++)
        if (!*prefix)
            return 0;
        else if (*str != *prefix)
            return (unsigned char)*prefix - (unsigned char)*str;
}

static void
argparse_error(struct argparse *self, struct argparse_option *opt,
               const char *reason)
{
    if (!strncmp(self->argv[0], "--", 2)) {
        fprintf(stderr, "error: option `%s` %s\n", opt->long_name, reason);
        exit(1);
    } else {
        fprintf(stderr, "error: option `%c` %s\n", opt->short_name, reason);
        exit(1);
    }
}

static int
argparse_getvalue(struct argparse *self, struct argparse_option *opt,
                  int flags)
{
    const char *s = NULL;

    if (opt->count == opt->max_count)
        argparse_error(self, opt, "repeated too many times");

    if (!opt->value)
        goto skipped;

    switch (opt->type) {
    case ARGPARSE_OPT_BOOLEAN:
        if (flags & OPT_UNSET) {
            *(int *)opt->value = *(int *)opt->value - 1;
        } else {
            *(int *)opt->value = *(int *)opt->value + 1;
        }
        if (*(int *)opt->value < 0) {
            *(int *)opt->value = 0;
        }
        break;
    case ARGPARSE_OPT_BIT:
        if (flags & OPT_UNSET) {
            *(int *)opt->value &= ~opt->data;
        } else {
            *(int *)opt->value |= opt->data;
        }
        break;
    case ARGPARSE_OPT_STRING:
        if (self->optvalue) {
            *(const char **)opt->value = self->optvalue;
            self->optvalue = NULL;
        } else if (self->argc > 1) {
            self->argc--;
            if (opt->max_count > 1) {
                ((const char**)opt->value)[opt->count] = *++self->argv;
            }
            else {
                *(const char **)opt->value = *++self->argv;
            }
        } else {
            argparse_error(self, opt, "requires a value");
        }
        break;
    case ARGPARSE_OPT_INTEGER:
        if (self->optvalue) {
            *(int *)opt->value = strtol(self->optvalue, (char **)&s, 0);
            self->optvalue = NULL;
        } else if (self->argc > 1) {
            self->argc--;
            if (opt->max_count > 1) {
                ((int*)opt->value)[opt->count] = strtol(*++self->argv, (char **)&s, 0);
            }
            else {
                *(int *)opt->value = strtol(*++self->argv, (char **)&s, 0);
            }
        } else {
            argparse_error(self, opt, "requires a value");
        }
        if (s[0] != '\0')
            argparse_error(self, opt, "expects a numerical value");
        break;
    default:
        assert(0);
    }

    opt->count++;

skipped:
    if (opt->callback) {
        return opt->callback(self, opt);
    }

    return 0;
}

static void
argparse_options_check(struct argparse_option *options)
{
    for (; options->type != ARGPARSE_OPT_END; options++) {
        switch (options->type) {
        case ARGPARSE_OPT_END:
        case ARGPARSE_OPT_BOOLEAN:
        case ARGPARSE_OPT_BIT:
        case ARGPARSE_OPT_INTEGER:
        case ARGPARSE_OPT_STRING:
        case ARGPARSE_OPT_GROUP:
            continue;
        default:
            fprintf(stderr, "wrong option type: %d", options->type);
            break;
        }
    }
}

static int
argparse_short_opt(struct argparse *self, struct argparse_option *options)
{
    for (; options->type != ARGPARSE_OPT_END; options++) {
        if (options->short_name == *self->optvalue) {
            self->optvalue = self->optvalue[1] ? self->optvalue + 1 : NULL;
            return argparse_getvalue(self, options, 0);
        }
    }
    return -2;
}

static int
argparse_long_opt(struct argparse *self, struct argparse_option *options)
{
    for (; options->type != ARGPARSE_OPT_END; options++) {
        const char *rest;
        int opt_flags = 0;
        if (!options->long_name)
            continue;

        rest = prefix_skip(self->argv[0] + 2, options->long_name);
        if (!rest) {
            // Negation allowed?
            if (options->flags & OPT_NONEG) {
                continue;
            }
            // Only boolean/bit allow negation.
            if (options->type != ARGPARSE_OPT_BOOLEAN && options->type != ARGPARSE_OPT_BIT) {
                continue;
            }

            if (!prefix_cmp(self->argv[0] + 2, "no-")) {
                rest = prefix_skip(self->argv[0] + 2 + 3, options->long_name);
                if (!rest)
                    continue;
                opt_flags |= OPT_UNSET;
            } else {
                continue;
            }
        }
        if (*rest) {
            if (*rest != '=')
                continue;
            self->optvalue = rest + 1;
        }
        return argparse_getvalue(self, options, opt_flags);
    }
    return -2;
}

int
argparse_init(struct argparse *self, struct argparse_option *options,
              const char *const *usage, int flags)
{
    memset(self, 0, sizeof(*self));
    self->options = options;
    self->usage = usage;
    self->flags = flags;

    for (; options->type != ARGPARSE_OPT_END; options++)
        options->count = 0;

    return 0;
}

int
argparse_parse(struct argparse *self, int argc, const char **argv)
{
    self->argc = argc - 1;
    self->argv = argv + 1;
    self->out = argv;

    argparse_options_check(self->options);

    for (; self->argc; self->argc--, self->argv++) {
        const char *arg = self->argv[0];
        if (arg[0] != '-' || !arg[1]) {
            if (self->flags & ARGPARSE_STOP_AT_NON_OPTION) {
                goto end;
            }
            // if it's not option or is a single char '-', copy verbatimly
            self->out[self->cpidx++] = self->argv[0];
            continue;
        }
        // short option
        if (arg[1] != '-') {
            self->optvalue = arg + 1;
            switch (argparse_short_opt(self, self->options)) {
            case -1:
                break;
            case -2:
                goto unknown;
            }
            while (self->optvalue) {
                switch (argparse_short_opt(self, self->options)) {
                case -1:
                    break;
                case -2:
                    goto unknown;
                }
            }
            continue;
        }
        // if '--' presents
        if (!arg[2]) {
            self->argc--;
            self->argv++;
            break;
        }
        // long option
        switch (argparse_long_opt(self, self->options)) {
        case -1:
            break;
        case -2:
            goto unknown;
        }
        continue;

unknown:
        fprintf(stderr, "error: unknown option `%s`\n", self->argv[0]);
        argparse_usage(self);
        exit(1);
    }

end:
    memmove(self->out + self->cpidx, self->argv,
            self->argc * sizeof(*self->out));
    self->out[self->cpidx + self->argc] = NULL;

    return self->cpidx + self->argc;
}

void
argparse_usage(struct argparse *self)
{
    fprintf(stdout, "Usage: %s\n", *self->usage++);
    while (*self->usage && **self->usage)
        fprintf(stdout, "   or: %s\n", *self->usage++);
    fputc('\n', stdout);

    struct argparse_option *options;

    // figure out best width
    size_t usage_opts_width = 0;
    size_t len;
    options = self->options;
    for (; options->type != ARGPARSE_OPT_END; options++) {
        len = 0;
        if ((options)->short_name) {
            len += 2;
        }
        if ((options)->short_name && (options)->long_name) {
            len += 2;           // separator ", "
        }
        if ((options)->long_name) {
            len += strlen((options)->long_name) + 2;
        }
        if (options->type == ARGPARSE_OPT_INTEGER) {
            len++; // equal sign "=" or space
            if (options->type_help != NULL)
                len += strlen(options->type_help);
            else
                len += strlen("<int>");
        } else if (options->type == ARGPARSE_OPT_STRING) {
            len++; // equal sign "=" or space
            if (options->type_help != NULL)
                len += strlen(options->type_help);
            else
                len += strlen("<str>");
        }
        len = (len / 4) * 4 + 4;
        if (usage_opts_width < len) {
            usage_opts_width = len;
        }
    }
    usage_opts_width += 4;      // 4 spaces prefix

    options = self->options;
    for (; options->type != ARGPARSE_OPT_END; options++) {
        size_t pos = 0;
        size_t pad = 0;
        if (options->type == ARGPARSE_OPT_GROUP) {
            fputc('\n', stdout);
            fprintf(stdout, "%s", options->help);
            fputc('\n', stdout);
            continue;
        }
        pos = fprintf(stdout, "    ");
        if (options->short_name) {
            pos += fprintf(stdout, "-%c", options->short_name);
        }
        if (options->long_name && options->short_name) {
            pos += fprintf(stdout, ", ");
        }
        if (options->long_name) {
            pos += fprintf(stdout, "--%s", options->long_name);
        }
        if (options->type == ARGPARSE_OPT_INTEGER) {
            if (options->long_name)
                pos += fprintf(stdout, "=");
            else
                pos += fprintf(stdout, " ");
            if (options->type_help != NULL)
                pos += fprintf(stdout, "%s", options->type_help);
            else
                pos += fprintf(stdout, "<int>");
        } else if (options->type == ARGPARSE_OPT_STRING) {
            if (options->long_name)
                pos += fprintf(stdout, "=");
            else
                pos += fprintf(stdout, " ");
            if (options->type_help != NULL)
                pos += fprintf(stdout, "%s", options->type_help);
            else
                pos += fprintf(stdout, "<str>");
        }
        if (pos <= usage_opts_width) {
            pad = usage_opts_width - pos;
        } else {
            fputc('\n', stdout);
            pad = usage_opts_width;
        }
        fprintf(stdout, "%*s%s\n", pad + 2, "", options->help);
    }
}

int
argparse_help_cb(struct argparse *self, const struct argparse_option *option)
{
    (void)option;
    argparse_usage(self);
    exit(0);
    return 0;
}
