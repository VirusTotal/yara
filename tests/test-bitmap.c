#include <yara.h>
#include "util.h"

static void test_re_with_alternation()
{
  assert_true_matches("rule test {strings: $a = /a(b|c)/ condition: $a }", "abacc", ((char*[]){"ab", "ac"}), 2);
  assert_true_matches("rule test {strings: $a = /a(b|c)/ condition: $a }", "abacc", ((char*[]){"ab", "ac"}), 2);
  assert_true_matches("rule test {strings: $a = /abc(d|)/ condition: $a }", "abcd", ((char*[]){"abcd"}), 1);
  assert_true_matches("rule test {strings: $a = /a(a|b|c)/ condition: $a}", "aabaac", ((char*[]){"aa", "ab", "aa", "ac"}), 4);
  assert_true_matches("rule test {strings: $a = /(aa|ab|ac)/ condition: $a}", "aabaac", ((char*[]){"aa", "ab", "aa", "ac"}), 4);
  assert_true_matches("rule test {strings: $a = /a[abc]/ condition: $a}", "aabaac",((char*[]){"aa", "ab", "aa", "ac"}), 4);
  assert_true_matches("rule test {strings: $a = /a[a-c]/ condition: $a}", "aabaac", ((char*[]){"aa", "ab", "aa", "ac"}), 4);
}

static void test_re_with_range()
{
  assert_true_matches("rule test {strings: $a = /a{2}/ condition: $a}", "aaaaa", ((char*[]){"aa", "aa", "aa", "aa"}), 4);
  assert_true_matches("rule test {strings: $a = /ab{2}/ condition: $a}", "ababb", ((char*[]){"abb"}), 1);
  assert_true_matches("rule test {strings: $a = /(ab){2}/ condition: $a}", "abbabab", ((char*[]){"abab"}), 1);
}

static void test_re_overlapping()
{
  assert_true_matches("rule test {strings: $a = /aaa/ condition: $a }", "aaaaa", ((char*[]){"aaa", "aaa", "aaa"}), 3);
  assert_true_matches("rule test {strings: $a = /abc/ $b = /bbb/ condition: $a or $b}", "abbbbabc", ((char*[]){"abc", "bbb", "bbb"}), 3);
  assert_true_matches("rule test {strings: $a = /abc/ $b = /bcb/ condition: $a or $b}", "abcbbabc", ((char*[]){"abc", "abc", "bcb"}), 3);
  assert_true_matches("rule test {strings: $a = /abc/ $b = /bdb/ condition: $a or $b}", "abcbdbdb", ((char*[]){"abc", "bdb", "bdb"}), 3);
}

static void test_re_node_any()
{
  assert_true_matches("rule test {strings: $a = /a.c/ condition: $a}", "aacc", ((char*[]){"aac", "acc"}), 2);
  assert_true_matches("rule test {strings: $a = /a../ condition: $a}", "aacc", ((char*[]){"aac", "acc"}), 2);
  assert_true_matches("rule test {strings: $a = /.../ condition: $a}", "aacc", ((char*[]){"aac", "acc"}), 2);
  assert_true_matches("rule test {strings: $a = /a.c./ condition: $a}", "aaccc", ((char*[]){"aacc", "accc"}), 2);
  assert_true_matches("rule test {strings: $a = /abc/ $b = /.bb/ condition: $a or $b}", "abcbbb", ((char*[]){"abc", "cbb", "bbb"}), 3);
  assert_true_matches("rule test {strings: $a = /.bd/ $d = /adc/ condition: $a or $d}", "adcbd", ((char*[]){"cbd", "adc"}), 2);
  assert_true_matches("rule test {strings: $a = /.b/ $b = /a.c/ condition: $a or $b}", "abc dbdb", ((char*[]){"ab", "db", "db", "abc"}), 4);
  assert_true_matches("rule test {strings: $a = /a.c/ $b = /.cd/ condition: $a or $b}", "abcd", ((char*[]){"abc", "bcd"}), 2);
  assert_true_matches("rule test {strings: $a = /(a.c)|(.cb)/ condition: $a}", "abcd", ((char*[]){"abc"}), 1);
  assert_true_matches("rule test {strings: $a = /(.bc)|(.cd)/ condition: $a}", "abcd", ((char*[]){"abc", "bcd"}), 2);
  assert_true_matches("rule test {strings: $a = /(a.c)/ $b = /b[a-d]d/ condition: $a or $b}", "abcd", ((char*[]){"abc", "bcd"}), 2);
  assert_true_matches("rule test {strings: $a = /b[a-d]d/ $b = /(a.c)/ condition: $a or $b}", "abcd", ((char*[]){"bcd", "abc"}), 2);

  assert_true_matches("rule test {strings: $a = /abc/ $b = /b.b/ condition: $a or $b}",
    "bbbbb abcb", ((char*[]){"abc", "bbb", "bbb", "bbb", "bcb"}), 5);

  assert_true_matches("rule test {strings: $a = /a.c/ $b = /.bc/ $c = /ab./ condition: $a or $b or $c}",
    "abc addbc", ((char*[]){"abc", "abc", "dbc", "abc"}), 4);

  assert_true_matches("rule test {strings: $a = /a.b/ $d = /a.c/ $e = /efg/ condition: $a or $d or $e}",
    "aabdecefg adbc", ((char*[]){"aab", "adb", "efg"}), 3);

    assert_true_matches("rule test {strings: $a = /a.b/ $d = /a.c/ $e = /e.g/ $f = /f.a/ condition: $a or $d or $e or $f}",
    "aabdecefgadbc", ((char*[]){"aab", "adb", "efg", "fga"}), 4);

    assert_true_matches("rule test {strings: $a = /a../ $d = /a.c/ $e = /e.g/ $f = /f.a/ condition: $a or $d or $e or $f}",
    "aabdecefgadbc", ((char*[]){"aab", "abd", "adb", "efg", "fga"}), 5);

  assert_true_matches("rule test {strings: $a = /a..d/ $d = /bcde/ $e = /efg/ condition: $a or $d or $e}",
    "abcdefg akld", ((char*[]){"abcd", "akld", "bcde", "efg"}), 4);

  assert_true_matches("rule test {strings: $a = /a..d/ $d = /bcde/ $k = /kl.n/ condition: $a or $d or $k}",
    "abcdefg akldn", ((char*[]){"abcd", "akld", "bcde", "kldn"}), 4);

  assert_true_matches("rule test {strings: $a = /e.b/ $b = /d.c/ $c = /a..d/ condition: $a or $b or $c}",
    "abbdacbeeb", ((char*[]){"eeb", "dac", "abbd"}), 3);

  assert_true_matches("rule test {strings: $a = /a.b/ $b = /d.c/ $c = /a..d/ condition: $a or $b or $c}",
    "abbdacb", ((char*[]){"abb", "acb", "dac", "abbd"}), 4);

  assert_true_matches("rule test {strings: $a = /.bc/ $b = /bb./ condition: $a or $b}",
    "bbdbbbcb", ((char*[]){"bbc", "bbd", "bbb", "bbc"}), 4);

  assert_true_matches("rule test {strings: $a = /.bc/ $b = /.cd/ $c = /.de/ condition: $a or $b or $c}",
    "abcde", ((char*[]){"abc", "bcd", "cde"}), 3);

  assert_true_matches("rule test {strings: $a = /b.c/ $b = /.bc/ $c = /bb./ $d = /a..d/ condition: $a or $b or $c or $d}",
    "bbdbbbcb abc addbc", ((char*[]){"bbc", "bbc", "abc", "dbc", "bbd", "bbb", "bbc"}), 7);

  assert_true_matches("rule test {strings: $a = /a.c/ $b = /.bc/ $c = /bb./ $d = /a..d/ condition: $a or $b or $c or $d}",
    "bbdbbbcb addbc abcd", ((char*[]){"abc", "bbc", "dbc", "abc", "bbd", "bbb", "bbc", "abcd"}), 8);

  assert_true_matches("rule test {strings: $a = /d.c/ $b = /.bc/ $c = /bb./ $d = /a..d/ condition: $a or $b or $c or $d}",
    "dbc abbd", ((char*[]){"dbc", "dbc", "bbd", "abbd"}), 4);

  assert_true_matches("rule test {strings: $a = /a..c/ $b = /a..d/ condition: $a or $b}",
    "aabcd", ((char*[]){"aabc", "abcd"}), 2);

  assert_true_matches("rule test {strings: $a = /ab../ $b = /..cd/ condition: $a or $b}",
    "abcd", ((char*[]){"abcd", "abcd"}), 2);

  assert_true_matches("rule test {strings: $a = /..ab/ $b = /..cd/ condition: $a or $b}",
    "xxabcd", ((char*[]){"xxab", "abcd"}), 2);

  assert_true_matches("rule test {strings: $a = /..ab/ $b = /..abd/ condition: $a or $b}",
    "xxabdabd", ((char*[]){"xxab", "bdab", "xxabd", "bdabd"}), 4);

  assert_true_matches("rule test {strings: $a = /a.cd/ $d = /de.g/ $e = /ghi./ $f = /abc/ condition: $a and $d and $e and $f}",
    "abcdefghijk", ((char*[]){"abcd", "defg", "ghij", "abc"}), 4);
}

static void test_hex()
{
  assert_true_matches("rule test {strings: $a = {31 3? 33} condition: $a}", "123133193 1m3", ((char*[]){"123", "133", "193"}), 3);
  assert_true_matches("rule test {strings: $a = {31 ?2 33} condition: $a}", "123 1B3 1r3 1m3", ((char*[]){"123", "1B3", "1r3"}), 3);
  assert_true_matches("rule test {strings: $a = {31 ?? 33} condition: $a}", "123 1B3 1r3 1m3", ((char*[]){"123", "1B3", "1r3", "1m3"}), 4);
}

static void test_class()
{
  assert_true_matches("rule test {strings: $a = /a[b-d]/ condition: $a}", "ab ac ad AB Ac aD", ((char*[]){"ab", "ac", "ad"}), 3);
  assert_true_matches("rule test {strings: $a = /a[bcd]/ condition: $a}", "ab ac ad AB Ac aD", ((char*[]){"ab", "ac", "ad"}), 3);
  assert_true_matches("rule test {strings: $a = /a[a-z]/ condition: $a}", "ab ac ad AB Ac aD", ((char*[]){"ab", "ac", "ad"}), 3);
  assert_true_matches("rule test {strings: $a = /a[a-mo-z]s/ condition: $a}", "abs azs ans", ((char*[]){"abs", "azs"}), 2);
  assert_true_matches("rule test {strings: $a = /a[^n]d/ condition: $a}", "abd azd and", ((char*[]){"abd", "azd"}), 2);
  assert_true_matches("rule test {strings: $a = /a[b-d]/ nocase condition: $a}", "ab ac ad AB Ac aD",
    ((char*[]){"ab", "ac", "ad", "AB", "Ac", "aD"}), 6);
  assert_true_matches("rule test {strings: $a = /[a-d]a/ $b = /[a-d]b/ condition: $a or $b}", "aa bb dab",
    ((char*[]){"aa", "da", "bb", "ab"}), 4);
  assert_true_matches("rule test {strings: $a = /a[a-d]/ $b = /b[a-d]/ condition: $a or $b}", "aa bb abc",
    ((char*[]){"aa", "ab", "bb", "bc"}), 4);
  assert_true_matches("rule test {strings: $a = /a[a-b]/ $b = /b[a-b]/ condition: $a or $b}", "aa bb abc",
    ((char*[]){"aa", "ab", "bb"}), 3);
  assert_true_matches("rule test {strings: $a = /a[a-d]/ $b = /b[a-d]/ $c = /c[a-d]/ $d = /d[a-d]/ condition: $a or $b or $c or $d}",
    "abcdd", ((char*[]){"ab", "bc", "cd", "dd"}), 4);
  assert_true_matches("rule test {strings: $a = /a.c/ $b = /[a-d]c/ condition: $a and $b}", "abc afc", ((char*[]){"abc", "afc", "bc"}), 3);
  assert_true_matches("rule test {strings: $a = /a.c/ $b = /b[a-f]c/ condition: $a and $b}", "abc bfc", ((char*[]){"abc", "bfc"}), 2);
  assert_true_matches("rule test {strings: $a = /[a-b]b/ $b = /b[c-d]/ condition: $a and $b}", "abc", ((char*[]){"ab", "bc"}), 2);
  assert_true_matches("rule test {strings: $a = /a[a-d]/ $b = /b[a-d]/ condition: $a and $b}", "abc", ((char*[]){"ab", "bc"}), 2);
  assert_true_matches("rule test {strings: $a = /[a-d]/ $b = /[a-b]/ condition: $a or $b}", "abc", ((char*[]){"a", "b", "c", "a", "b"}), 5);
  assert_true_matches("rule test {strings: $a = /a[a-d]/ $b = /[b-e]d/ condition: $a or $b}", "abcd", ((char*[]){"ab", "cd"}), 2);
  assert_true_matches("rule test {strings: $a = /[b-e]d/ $b = /a[a-d]/ condition: $a or $b}", "abcd", ((char*[]){"cd", "ab"}), 2);
  assert_true_matches("rule test {strings: $a = /[a-b]/ $b = /[a-d]/ condition: $a or $b}", "ad", ((char*[]){"a", "a", "d"}), 3);
  assert_true_matches("rule test {strings: $a = /u/ nocase $b = /u/ $c = /U/ condition: $a or $b or $c}", "uU",
    ((char*[]){"u", "U", "u", "U"}), 4);
  assert_true_matches("rule test {strings: $re1 = /1[a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword $re2 = /3[a-km-zA-HJ-NP-Z1-9]{25,34}/ fullword condition: $re1 or $re2}",
    "1JHwenDp9A98XdjfYkHKyiE3R99Q72K9X4 3DXWP9YVkAYwkmif9RgKeoPhw2b1zdMnMzXZSGRD", ((char*[]){"1JHwenDp9A98XdjfYkHKyiE3R99Q72K9X4"}), 1);
}


int main(int argc, char** argv)
{
  yr_initialize();
  test_re_with_alternation();
  test_re_with_range();
  test_re_overlapping();
  test_re_node_any();
  test_hex();
  test_class();
  yr_finalize();
  return 0;
}
