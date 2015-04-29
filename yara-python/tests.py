#
# Copyright (c) 2007-2014. The YARA Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import tempfile
import binascii
import os
import sys
import unittest
import yara
# Python 2/3
try:
    import StringIO
except:
    import io

PE32_FILE = binascii.unhexlify('\
4d5a000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000040000000\
504500004c0101005dbe45450000000000000000e00003010b01080004000000\
0000000000000000600100006001000064010000000040000100000001000000\
0400000000000000040000000000000064010000600100000000000002000004\
0000100000100000000010000010000000000000100000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000002e74657874000000\
0400000060010000040000006001000000000000000000000000000020000060\
6a2a58c3')

ELF32_FILE = binascii.unhexlify('\
7f454c4601010100000000000000000002000300010000006080040834000000\
a800000000000000340020000100280004000300010000000000000000800408\
008004086c0000006c0000000500000000100000000000000000000000000000\
b801000000bb2a000000cd8000546865204e65747769646520417373656d626c\
657220322e30352e303100002e7368737472746162002e74657874002e636f6d\
6d656e7400000000000000000000000000000000000000000000000000000000\
000000000000000000000000000000000b000000010000000600000060800408\
600000000c000000000000000000000010000000000000001100000001000000\
00000000000000006c0000001f00000000000000000000000100000000000000\
010000000300000000000000000000008b0000001a0000000000000000000000\
0100000000000000')

ELF64_FILE = binascii.unhexlify('\
7f454c4602010100000000000000000002003e00010000008000400000000000\
4000000000000000c80000000000000000000000400038000100400004000300\
0100000005000000000000000000000000004000000000000000400000000000\
8c000000000000008c0000000000000000002000000000000000000000000000\
b801000000bb2a000000cd8000546865204e65747769646520417373656d626c\
657220322e30352e303100002e7368737472746162002e74657874002e636f6d\
6d656e7400000000000000000000000000000000000000000000000000000000\
0000000000000000000000000000000000000000000000000000000000000000\
00000000000000000b0000000100000006000000000000008000400000000000\
80000000000000000c0000000000000000000000000000001000000000000000\
0000000000000000110000000100000000000000000000000000000000000000\
8c000000000000001f0000000000000000000000000000000100000000000000\
0000000000000000010000000300000000000000000000000000000000000000\
ab000000000000001a0000000000000000000000000000000100000000000000\
0000000000000000')

# The 3 possible outcomes for each pattern
[SUCCEED, FAIL, SYNTAX_ERROR] = range(3)


RE_TESTS = [

  # RE, string, expected result, expected matching

  (')', '', SYNTAX_ERROR),
  ('abc', 'abc', SUCCEED, 'abc'),
  ('abc', 'xbc', FAIL),
  ('abc', 'axc', FAIL),
  ('abc', 'abx', FAIL),
  ('abc', 'xabcx', SUCCEED, 'abc'),
  ('abc', 'ababc', SUCCEED, 'abc'),
  ('a.c', 'abc', SUCCEED, 'abc'),
  ('a.b', 'a\nb', FAIL),
  ('a.*b', 'acc\nccb', FAIL),
  ('a.{4,5}b', 'acc\nccb', FAIL),
  ('a.b', 'a\rb', SUCCEED, 'a\rb'),
  ('ab*c', 'abc', SUCCEED, 'abc'),
  ('ab*c', 'ac', SUCCEED, 'ac'),
  ('ab*bc', 'abc', SUCCEED, 'abc'),
  ('ab*bc', 'abbc', SUCCEED, 'abbc'),
  ('a.*c', 'ac', SUCCEED, 'ac'),
  ('a.*c', 'axyzc', SUCCEED, 'axyzc'),
  ('ab+c', 'abbc', SUCCEED, 'abbc'),
  ('ab+c', 'ac', FAIL),
  ('ab+', 'abbbb', SUCCEED, 'abbbb'),
  ('ab+?', 'abbbb', SUCCEED, 'ab'),
  ('ab+bc', 'abc', FAIL),
  ('ab+bc', 'abq', FAIL),
  ('a+b+c', 'aabbabc', SUCCEED, 'abc'),
  ('ab?bc', 'abbbbc', FAIL),
  ('ab?c', 'abc', SUCCEED, 'abc'),
  ('ab*?', 'abbb', SUCCEED, 'a'),
  ('ab?c', 'abc', SUCCEED, 'abc'),
  ('ab??', 'ab', SUCCEED, 'a'),
  ('a(b|x)c', 'abc', SUCCEED, 'abc'),
  ('a(b|x)c', 'axc', SUCCEED, 'axc'),
  ('a(b|.)c', 'axc', SUCCEED, 'axc'),
  ('a(b|x|y)c', 'ayc', SUCCEED, 'ayc'),
  ('(a+|b)*', 'ab', SUCCEED, 'ab'),
  ('a|b|c|d|e', 'e', SUCCEED, 'e'),
  ('(a|b|c|d|e)f', 'ef', SUCCEED, 'ef'),
  ('.b{2}', 'abb', SUCCEED, 'abb'),
  ('ab{1}c', 'abc', SUCCEED, 'abc'),
  ('ab{1,2}c', 'abbc', SUCCEED, 'abbc'),
  ('ab{1,}c', 'abbbc', SUCCEED, 'abbbc'),
  ('ab{1,}b', 'ab', FAIL),
  ('ab{1}c', 'abbc', FAIL),
  ('ab{0,}c', 'ac', SUCCEED, 'ac'),
  ('ab{0,}c', 'abbbc', SUCCEED, 'abbbc'),
  ('ab{,3}c', 'abbbc', SUCCEED, 'abbbc'),
  ('ab{,2}c', 'abbbc', FAIL),
  ('ab{4,5}bc', 'abbbbc', FAIL),
  ('ab{.*}', 'ab{c}', SUCCEED, 'ab{c}'),
  ('(ab{1,2}c){1,3}', 'abbcabc', SUCCEED, 'abbcabc'),
  ('ab(c|cc){1,3}d', 'abccccccd', SUCCEED, 'abccccccd'),
  ('a[bx]c', 'abc', SUCCEED, 'abc'),
  ('a[bx]c', 'axc', SUCCEED, 'axc'),
  ('a[0-9]*b', 'ab', SUCCEED, 'ab'),
  ('a[0-9]*b', 'a0123456789b', SUCCEED, 'a0123456789b'),
  ('[0-9a-f]+', '0123456789abcdef', SUCCEED, '0123456789abcdef'),
  ('[0-9a-f]+', 'xyz0123456789xyz', SUCCEED, '0123456789'),
  ('a[\s\S]b', 'a b', SUCCEED, 'a b'),
  ('a[\d\D]b', 'a1b', SUCCEED, 'a1b'),
  ('[x-z]+', 'abc', FAIL),
  ('a[-]?c', 'ac', SUCCEED, 'ac'),
  ('a[-b]', 'a-', SUCCEED, 'a-'),
  ('a[-b]', 'ab', SUCCEED, 'ab'),
  ('a[b-]', 'a-', SUCCEED, 'a-'),
  ('a[b-]', 'ab', SUCCEED, 'ab'),
  ('[a-c-e]', 'b', SUCCEED, 'b'),
  ('[a-c-e]', '-', SUCCEED, '-'),
  ('[a-c-e]', 'd', FAIL),
  ('[b-a]', '', SYNTAX_ERROR),
  ('(abc', '', SYNTAX_ERROR),
  ('abc)', '', SYNTAX_ERROR),
  ('a[]b', '', SYNTAX_ERROR),
  ('a\\', '', SYNTAX_ERROR),
  ('a[\\-b]', 'a-', SUCCEED, 'a-'),
  ('a[\\-b]', 'ab', SUCCEED, 'ab'),
  ('a[\\', '', SYNTAX_ERROR),
  ('a]', 'a]', SUCCEED, 'a]'),
  ('a[]]b', 'a]b', SUCCEED, 'a]b'),
  ('a[\]]b', 'a]b', SUCCEED, 'a]b'),
  ('a[^bc]d', 'aed', SUCCEED, 'aed'),
  ('a[^bc]d', 'abd', FAIL),
  ('a[^-b]c', 'adc', SUCCEED, 'adc'),
  ('a[^-b]c', 'a-c', FAIL),
  ('a[^]b]c', 'a]c', FAIL),
  ('a[^]b]c', 'adc', SUCCEED, 'adc'),
  ('[^ab]*', 'cde', SUCCEED, 'cde'),
  (')(', '', SYNTAX_ERROR),
  (r'a\sb', 'a b', SUCCEED, 'a b'),
  (r'a\sb', 'a\tb', SUCCEED, 'a\tb'),
  (r'a\sb', 'a\rb', SUCCEED, 'a\rb'),
  (r'a\sb', 'a\nb', SUCCEED, 'a\nb'),
  (r'a\sb', 'a\vb', SUCCEED, 'a\vb'),
  (r'a\sb', 'a\fb', SUCCEED, 'a\fb'),
  (r'a\Sb', 'a b', FAIL),
  (r'a\Sb', 'a\tb', FAIL),
  (r'a\Sb', 'a\rb', FAIL),
  (r'a\Sb', 'a\nb', FAIL),
  (r'a\Sb', 'a\vb', FAIL),
  (r'a\Sb', 'a\fb', FAIL),
  (r'\n\r\t\f\a', '\n\r\t\f\a', SUCCEED, '\n\r\t\f\a'),
  (r'[\n][\r][\t][\f][\a]', '\n\r\t\f\a', SUCCEED, '\n\r\t\f\a'),
  (r'\x00\x01\x02', '\x00\x01\x02', SUCCEED, '\x00\x01\x02'),
  (r'[\x00-\x02]+', '\x00\x01\x02', SUCCEED, '\x00\x01\x02'),
  (r'[\x00-\x02]+', '\x03\x04\x05', FAIL),
  (r'[\x5D]', ']', SUCCEED, ']'),
  (r'[\0x5A-\x5D]', '\x5B', SUCCEED, '\x5B'),
  (r'[\x5D-\x5F]', '\x5E', SUCCEED, '\x5E'),
  (r'[\x5C-\x5F]', '\x5E', SUCCEED, '\x5E'),
  (r'[\x5D-\x5F]', '\x5E', SUCCEED, '\x5E'),
  ('a\wc', 'abc', SUCCEED, 'abc'),
  ('a\wc', 'a_c', SUCCEED, 'a_c'),
  ('a\wc', 'a0c', SUCCEED, 'a0c'),
  ('a\wc', 'a*c', FAIL),
  ('\w+', '--ab_cd0123--', SUCCEED, 'ab_cd0123'),
  ('[\w]+', '--ab_cd0123--', SUCCEED, 'ab_cd0123'),
  ('\D+', '1234abc5678', SUCCEED, 'abc'),
  ('[\d]+', '0123456789', SUCCEED, '0123456789'),
  ('[\D]+', '1234abc5678', SUCCEED, 'abc'),
  ('[\da-fA-F]+', '123abc', SUCCEED, '123abc'),
  ('^(ab|cd)e', 'abcde', FAIL),
  ('(abc|)ef', 'abcdef', SUCCEED, 'ef'),
  ('(abc|)ef', 'abcef', SUCCEED, 'abcef'),
  (r'\babc', 'abc', SUCCEED, 'abc'),
  (r'abc\b', 'abc', SUCCEED, 'abc'),
  (r'\babc', '1abc', FAIL),
  (r'abc\b', 'abc1', FAIL),
  (r'abc\s\b', 'abc x', SUCCEED, 'abc '),
  (r'abc\s\b', 'abc  ', FAIL),
  (r'\babc\b', ' abc ', SUCCEED, 'abc'),
  (r'\b\w\w\w\b', ' abc ', SUCCEED, 'abc'),
  (r'\w\w\w\b', 'abcd', SUCCEED, 'bcd'),
  (r'\b\w\w\w', 'abcd', SUCCEED, 'abc'),
  (r'\b\w\w\w\b', 'abcd', FAIL),
  (r'\Babc', 'abc', FAIL),
  (r'abc\B', 'abc', FAIL),
  (r'\Babc', '1abc', SUCCEED, 'abc'),
  (r'abc\B', 'abc1', SUCCEED, 'abc'),
  (r'abc\s\B', 'abc x', FAIL),
  (r'abc\s\B', 'abc  ', SUCCEED, 'abc '),
  (r'\w\w\w\B', 'abcd', SUCCEED, 'abc'),
  (r'\B\w\w\w', 'abcd', SUCCEED, 'bcd'),
  (r'\B\w\w\w\B', 'abcd', FAIL),

  # This is allowed in most regexp engines but in order to keep the
  # grammar free of shift/reduce conflicts I've decided not supporting
  # it. Users can use the (abc|) form instead.

  ('(|abc)ef', '', SYNTAX_ERROR),

  ('((a)(b)c)(d)', 'abcd', SUCCEED, 'abcd'),
  ('(a|b)c*d', 'abcd', SUCCEED, 'bcd'),
  ('(ab|ab*)bc', 'abc', SUCCEED, 'abc'),
  ('a([bc]*)c*', 'abc', SUCCEED, 'abc'),
  ('a([bc]*)c*', 'ac', SUCCEED, 'ac'),
  ('a([bc]*)c*', 'a', SUCCEED, 'a'),
  ('a([bc]*)(c*d)', 'abcd', SUCCEED, 'abcd'),
  ('a([bc]+)(c*d)', 'abcd', SUCCEED, 'abcd'),
  ('a([bc]*)(c+d)', 'abcd', SUCCEED, 'abcd'),
  ('a[bcd]*dcdcde', 'adcdcde', SUCCEED, 'adcdcde'),
  ('a[bcd]+dcdcde', 'adcdcde', FAIL),
  (r'\((.*), (.*)\)', '(a, b)', SUCCEED, '(a, b)'),
  ('abc|123$', 'abcx', SUCCEED, 'abc'),
  ('abc|123$', '123x', FAIL),
  ('abc|^123', '123', SUCCEED, '123'),
  ('abc|^123', 'x123', FAIL),
  ('^abc$', 'abc', SUCCEED, 'abc'),
  ('^abc$', 'abcc', FAIL),
  ('^abc', 'abcc', SUCCEED, 'abc'),
  ('^abc$', 'aabc', FAIL),
  ('abc$', 'aabc', SUCCEED, 'abc'),
  ('^a(bc+|b[eh])g|.h$', 'abhg', SUCCEED, 'abhg'),
  ('(bc+d$|ef*g.|h?i(j|k))', 'effgz', SUCCEED, 'effgz'),
  ('(bc+d$|ef*g.|h?i(j|k))', 'ij', SUCCEED, 'ij'),
  ('(bc+d$|ef*g.|h?i(j|k))', 'effg', FAIL),
  ('(bc+d$|ef*g.|h?i(j|k))', 'bcdd', FAIL),
  ('(bc+d$|ef*g.|h?i(j|k))', 'reffgz', SUCCEED, 'effgz'),

]


class TestYara(unittest.TestCase):

    def assertTrueRules(self, rules, data='dummy'):

        for r in rules:
            r = yara.compile(source=r)
            self.assertTrue(r.match(data=data))

    def assertFalseRules(self, rules, data='dummy'):

        for r in rules:
            r = yara.compile(source=r)
            self.assertFalse(r.match(data=data))

    def runReTest(self, test):

        regexp = test[0]
        string = test[1]
        expected_result = test[2]

        source = 'rule test { strings: $a = /%s/ condition: $a }' % regexp

        if expected_result == SYNTAX_ERROR:
          self.assertRaises(yara.SyntaxError, yara.compile, source=source)
        else:
          rule = yara.compile(source=source)
          matches = rule.match(data=string)
          if expected_result == SUCCEED:
            self.assertTrue(matches)
            _, _, matching_string = matches[0].strings[0]
            if sys.version_info[0] >= 3:
              self.assertTrue(matching_string == bytes(test[3], 'utf-8'))
            else:
              self.assertTrue(matching_string == test[3])
          else:
            self.assertFalse(matches)

    def testBooleanOperators(self):

        self.assertTrueRules([
            'rule test { condition: true }',
            'rule test { condition: true or false }',
            'rule test { condition: true and true }',
            'rule test { condition: 0x1 and 0x2}',
        ])

        self.assertFalseRules([
            'rule test { condition: false }',
            'rule test { condition: true and false }',
            'rule test { condition: false or false }'
        ])

    def testComparisonOperators(self):

        self.assertTrueRules([
            'rule test { condition: 2 > 1 }',
            'rule test { condition: 1 < 2 }',
            'rule test { condition: 2 >= 1 }',
            'rule test { condition: 1 <= 1 }',
            'rule test { condition: 1 == 1 }',
            'rule test { condition: 1.5 == 1.5}',
            'rule test { condition: 1.0 == 1}',
            'rule test { condition: 1.5 >= 1.0}',
            'rule test { condition: 1.5 >= 1}',
            'rule test { condition: 1.0 >= 1}',
            'rule test { condition: 0.5 < 1}',
            'rule test { condition: 0.5 <= 1}',
            'rule rest { condition: 1.0 <= 1}',
            'rule rest { condition: "abc" == "abc"}',
            'rule rest { condition: "abc" <= "abc"}',
            'rule rest { condition: "abc" >= "abc"}',
            'rule rest { condition: "ab" < "abc"}',
            'rule rest { condition: "abc" > "ab"}',
            'rule rest { condition: "abc" < "abd"}',
            'rule rest { condition: "abd" > "abc"}',
        ])

        self.assertFalseRules([
            'rule test { condition: 1 != 1}',
            'rule test { condition: 1 != 1.0}',
            'rule test { condition: 2 > 3}',
            'rule test { condition: 2.1 < 2}',
            'rule test { condition: "abc" != "abc"}',
            'rule test { condition: "abc" > "abc"}',
            'rule test { condition: "abc" < "abc"}',
        ])

    def testArithmeticOperators(self):

        self.assertTrueRules([
            'rule test { condition: (1 + 1) * 2 == (9 - 1) \ 2 }',
            'rule test { condition: 5 % 2 == 1 }',
            'rule test { condition: 1.5 + 1.5 == 3}',
            'rule test { condition: 3 \ 2 == 1}',
            'rule test { condition: 3.0 \ 2 == 1.5}',
            'rule test { condition: 1 + -1 == 0}',
            'rule test { condition: -1 + -1 == -2}',
            'rule test { condition: 4 --2 * 2 == 8}',
            'rule test { condition: -1.0 * 1 == -1.0}',
            'rule test { condition: 1-1 == 0}',
            'rule test { condition: -2.0-3.0 == -5}',
            'rule test { condition: --1 == 1}',
            'rule test { condition: 1--1 == 2}',
            'rule test { condition: -0x01 == -1}',
        ])

    def testBitwiseOperators(self):

        self.assertTrueRules([
            'rule test { condition: 0x55 | 0xAA == 0xFF }',
            'rule test { condition: ~0xAA ^ 0x5A & 0xFF == (~0xAA) ^ (0x5A & 0xFF) }',
            'rule test { condition: ~0x55 & 0xFF == 0xAA }',
            'rule test { condition: 8 >> 2 == 2 }',
            'rule test { condition: 1 << 3 == 8 }',
            'rule test { condition: 1 | 3 ^ 3 == 1 | (3 ^ 3) }'
            ])

        self.assertFalseRules([
            'rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }',
            'rule test { condition: 1 | 3 ^ 3 == (1 | 3) ^ 3}'
        ])

    def testStrings(self):

        self.assertTrueRules([
            'rule test { strings: $a = "a" condition: $a }',
            'rule test { strings: $a = "ab" condition: $a }',
            'rule test { strings: $a = "abc" condition: $a }',
            'rule test { strings: $a = "xyz" condition: $a }',
            'rule test { strings: $a = "abc" nocase fullword condition: $a }',
            'rule test { strings: $a = "aBc" nocase  condition: $a }',
            'rule test { strings: $a = "abc" fullword condition: $a }',
        ], "---- abc ---- xyz")

        self.assertFalseRules([
            'rule test { strings: $a = "a" fullword condition: $a }',
            'rule test { strings: $a = "ab" fullword condition: $a }',
            'rule test { strings: $a = "abc" wide fullword condition: $a }',
        ], "---- abc ---- xyz")

        self.assertTrueRules([
            'rule test { strings: $a = "a" wide condition: $a }',
            'rule test { strings: $a = "a" wide ascii condition: $a }',
            'rule test { strings: $a = "ab" wide condition: $a }',
            'rule test { strings: $a = "ab" wide ascii condition: $a }',
            'rule test { strings: $a = "abc" wide condition: $a }',
            'rule test { strings: $a = "abc" wide nocase fullword condition: $a }',
            'rule test { strings: $a = "aBc" wide nocase condition: $a }',
            'rule test { strings: $a = "aBc" wide ascii nocase condition: $a }',
            'rule test { strings: $a = "---xyz" wide nocase condition: $a }'
        ], "---- a\x00b\x00c\x00 -\x00-\x00-\x00-\x00x\x00y\x00z\x00")

        self.assertTrueRules([
            'rule test { strings: $a = "abc" fullword condition: $a }',
        ], "abc")

        self.assertFalseRules([
            'rule test { strings: $a = "abc" fullword condition: $a }',
        ], "xabcx")

        self.assertFalseRules([
            'rule test { strings: $a = "abc" fullword condition: $a }',
        ], "xabc")

        self.assertFalseRules([
            'rule test { strings: $a = "abc" fullword condition: $a }',
        ], "abcx")

        self.assertFalseRules([
            'rule test { strings: $a = "abc" ascii wide fullword condition: $a }',
        ], "abcx")

        self.assertTrueRules([
            'rule test { strings: $a = "abc" ascii wide fullword condition: $a }',
        ], "a\x00abc")

        self.assertTrueRules([
            'rule test { strings: $a = "abc" wide fullword condition: $a }',
        ], "a\x00b\x00c\x00")

        self.assertFalseRules([
            'rule test { strings: $a = "abc" wide fullword condition: $a }',
        ], "x\x00a\x00b\x00c\x00x\x00")

        self.assertFalseRules([
            'rule test { strings: $a = "ab" wide fullword condition: $a }',
        ], "x\x00a\x00b\x00")

        self.assertFalseRules([
            'rule test { strings: $a = "abc" wide fullword condition: $a }',
        ], "x\x00a\x00b\x00c\x00")

        self.assertTrueRules([
            'rule test { strings: $a = "abc" wide fullword condition: $a }',
        ], "x\x01a\x00b\x00c\x00")

        self.assertTrueRules([
            'rule test {\
                strings:\
                    $a = "abcdef"\
                    $b = "cdef"\
                    $c = "ef"\
                condition:\
                    all of them\
             }'
        ], 'abcdef')

    def testWildcardStrings(self):

        self.assertTrueRules([
            'rule test {\
                strings:\
                    $s1 = "abc"\
                    $s2 = "xyz"\
                condition:\
                    for all of ($*) : ($)\
             }'
        ], "---- abc ---- A\x00B\x00C\x00 ---- xyz")

    def testHexStrings(self):

        self.assertTrueRules([
            'rule test { strings: $a = { 64 01 00 00 60 01 } condition: $a }',
            'rule test { strings: $a = { 64 0? 00 00 ?0 01 } condition: $a }',
            'rule test { strings: $a = { 64 01 [1-3] 60 01 } condition: $a }',
            'rule test { strings: $a = { 64 01 [1-3] (60|61) 01 } condition: $a }',
            'rule test { strings: $a = { 4D 5A [-] 6A 2A [-] 58 C3} condition: $a }',
            'rule test { strings: $a = { 4D 5A [300-] 6A 2A [-] 58 C3} condition: $a }'
        ], PE32_FILE)

        self.assertFalseRules([
            'rule test { strings: $a = { 4D 5A [0-300] 6A 2A } condition: $a }'
        ], PE32_FILE)

        self.assertTrueRules([
          'rule test { strings: $a = { 31 32 [-] 38 39 } condition: $a }',
          'rule test { strings: $a = { 31 32 [-] 33 34 [-] 38 39 } condition: $a }',
          'rule test { strings: $a = { 31 32 [1] 34 35 [2] 38 39 } condition: $a }',
          'rule test { strings: $a = { 31 32 [1-] 34 35 [1-] 38 39 } condition: $a }',
          'rule test { strings: $a = { 31 32 [0-3] 34 35 [1-] 38 39 } condition: $a }',
        ], '123456789')

        self.assertTrueRules([
          'rule test { strings: $a = { 31 32 [-] 38 39 } condition: all of them }',
        ], '123456789')

        self.assertFalseRules([
          'rule test { strings: $a = { 31 32 [-] 32 33 } condition: $a }',
          'rule test { strings: $a = { 35 36 [-] 31 32 } condition: $a }',
          'rule test { strings: $a = { 31 32 [2-] 34 35 } condition: $a }',
          'rule test { strings: $a = { 31 32 [0-3] 37 38 } condition: $a }',
        ], '123456789')

        rules = yara.compile(source='rule test { strings: $a = { 61 [0-3] (62|63) } condition: $a }')
        matches = rules.match(data='abbb')

        if sys.version_info[0] >= 3:
          self.assertTrue(matches[0].strings == [(0, '$a', bytes('ab', 'utf-8'))])
        else:
          self.assertTrue(matches[0].strings == [(0, '$a', 'ab')])

    def testCount(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" condition: #a == 2 }',
        ], 'mississippi')

    def testAt(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" condition: $a at 2 and $a at 5 }',
            'rule test { strings: $a = "mis" condition: $a at ~0xFF & 0xFF }'
        ], 'mississippi')

        self.assertTrueRules([
            'rule test { strings: $a = { 00 00 00 00 ?? 74 65 78 74 } condition: $a at 308}',
        ], PE32_FILE)

    def testOffset(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" condition: @a == 2 }',
            'rule test { strings: $a = "ssi" condition: @a == @a[1] }',
            'rule test { strings: $a = "ssi" condition: @a[2] == 5 }'
        ], 'mississippi')

    def testOf(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: any of them }',
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: 1 of them }',
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: 2 of them }',
            'rule test { strings: $a1 = "dummy1" $b1 = "dummy1" $b2 = "ssi" condition: any of ($a*, $b*) }',
        ], 'mississipi')

        self.assertTrueRules(["""
            rule test
            {
              strings:
                $ = /abc/
                $ = /def/
                $ = /ghi/
              condition:
                for any of ($*) : ( for any i in (1..#): (uint8(@[i] - 1) == 0x00) )
            }"""
        ], 'abc\x00def\x00ghi')

        self.assertFalseRules([
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: all of them }'
        ], 'mississipi')

    def testFor(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" condition: for all i in (1..#a) : (@a[i] >= 2 and @a[i] <= 5) }',
            'rule test { strings: $a = "ssi" $b = "mi" condition: for all i in (1..#a) : ( for all j in (1..#b) : (@a[i] >= @b[j])) }'
        ], 'mississipi')

        self.assertFalseRules([
            'rule test { strings: $a = "ssi" condition: for all i in (1..#a) : (@a[i] == 5) }',
        ], 'mississipi')

    def testRE(self):

        self.assertTrueRules([
            'rule test { strings: $a = /ssi/ condition: $a }',
            'rule test { strings: $a = /ssi(s|p)/ condition: $a }',
            'rule test { strings: $a = /ssim*/ condition: $a }',
            'rule test { strings: $a = /ssa?/ condition: $a }',
            'rule test { strings: $a = /Miss/ nocase condition: $a }',
            'rule test { strings: $a = /(M|N)iss/ nocase condition: $a }',
            'rule test { strings: $a = /[M-N]iss/ nocase condition: $a }',
            'rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }',
            'rule test { strings: $a = /ppi\tmi/ condition: $a }',
            'rule test { strings: $a = /ppi\.mi/ condition: $a }',
            'rule test { strings: $a = /^mississippi/ fullword condition: $a }',
            'rule test { strings: $a = /mississippi.*mississippi$/s condition: $a }',
        ], 'mississippi\tmississippi.mississippi\nmississippi')

        self.assertFalseRules([
            'rule test { strings: $a = /^ssi/ condition: $a }',
            'rule test { strings: $a = /ssi$/ condition: $a }',
            'rule test { strings: $a = /ssissi/ fullword condition: $a }',
            'rule test { strings: $a = /^[isp]+/ condition: $a }'
        ], 'mississippi')

        for test in RE_TESTS:
            try:
                self.runReTest(test)
            except Exception as e:
                print('\nFailed test: %s\n' % str(test))
                raise e

    def testEntrypoint(self):

        self.assertTrueRules([
            'rule test { strings: $a = { 6a 2a 58 c3 } condition: $a at entrypoint }',
        ], PE32_FILE)

        self.assertTrueRules([
            'rule test { strings: $a = { b8 01 00 00 00 bb 2a } condition: $a at entrypoint }',
        ], ELF32_FILE)

        self.assertTrueRules([
            'rule test { strings: $a = { b8 01 00 00 00 bb 2a } condition: $a at entrypoint }',
        ], ELF64_FILE)

        self.assertFalseRules([
            'rule test { condition: entrypoint >= 0 }',
        ])

    def testFilesize(self):

        self.assertTrueRules([
            'rule test { condition: filesize == %d }' % len(PE32_FILE),
        ], PE32_FILE)

    def testCompileFile(self):

        f = tempfile.TemporaryFile('wt')

        f.write('rule test { condition: true }')
        f.flush()
        f.seek(0)

        r = yara.compile(file=f)
        f.close()
        self.assertTrue(r.match(data=PE32_FILE))

    def testCompileFiles(self):

        tmpdir = tempfile.gettempdir()

        p1 = os.path.join(tmpdir, 'test1')
        f1 = open(p1, 'wt')
        f1.write('rule test1 { condition: true }')
        f1.close()

        p2 = os.path.join(tmpdir, 'test2')
        t2 = open(p2, 'wt')
        t2.write('rule test2 { condition: true }')
        t2.close()

        r = yara.compile(filepaths={
            'test1': p1,
            'test2': p2
        })

        self.assertTrue(len(r.match(data='dummy')) == 2)

        for m in r.match(data='dummy'):
            self.assertTrue(m.rule in ('test1', 'test2'))
            self.assertTrue(m.namespace == m.rule)

        os.remove(p1)
        os.remove(p2)

    def testIncludeFiles(self):

        tmpdir = tempfile.gettempdir()

        p1 = os.path.join(tmpdir, 'test1')
        f1 = open(p1, 'wt')
        f1.write('rule test1 { condition: true }')
        f1.close()

        p2 = os.path.join(tmpdir, 'test2')
        f2 = open(p2, 'wt')
        f2.write('include "%s" rule test2 { condition: test1 }' % p1)
        f2.close()

        r = yara.compile(p2)
        self.assertTrue(len(r.match(data='dummy')) == 2)

    def testExternals(self):

        r = yara.compile(source='rule test { condition: ext_int == 15 }', externals={'ext_int': 15})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_int == -15}', externals={'ext_int': -15})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_float == 3.14 }', externals={'ext_float': 3.14})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_float == -0.5 }', externals={'ext_float': -0.5})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_bool }', externals={'ext_bool': True})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str }', externals={'ext_str': ''})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str }', externals={'ext_str': 'foo'})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_bool }', externals={'ext_bool': False})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str contains "ssi" }', externals={'ext_str': 'mississippi'})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /foo/ }', externals={'ext_str': ''})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /foo/ }', externals={'ext_str': 'FOO'})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /foo/i }', externals={'ext_str': 'FOO'})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /ssi(s|p)/ }', externals={'ext_str': 'mississippi'})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /ppi$/ }', externals={'ext_str': 'mississippi'})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /ssi$/ }', externals={'ext_str': 'mississippi'})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /^miss/ }', externals={'ext_str': 'mississippi'})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /^iss/ }', externals={'ext_str': 'mississippi'})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /ssi$/ }', externals={'ext_str': 'mississippi'})
        self.assertFalse(r.match(data='dummy'))

    def testCallback(self):

        global rule_data
        rule_data = None

        def callback(data):
            global rule_data
            rule_data = data
            return yara.CALLBACK_CONTINUE

        r = yara.compile(source='rule test { strings: $a = { 50 45 00 00 4c 01 } condition: $a }')
        r.match(data=PE32_FILE, callback=callback)

        self.assertTrue(rule_data['matches'])
        self.assertTrue(rule_data['rule'] == 'test')

    def testCompare(self):

        r = yara.compile(sources={
            'test1': 'rule test { condition: true}',
            'test2': 'rule test { condition: true}'
        })

        m = r.match(data="dummy")

        self.assertTrue(len(m) == 2)
        self.assertTrue(m[0] < m[1])
        self.assertTrue(m[0] != m[1])
        self.assertFalse(m[0] > m[1])
        self.assertFalse(m[0] == m[1])

    def testComments(self):

        self.assertTrueRules([
            """
            rule test {
                condition:
                    //  this is a comment
                    /*** this is a comment ***/
                    /* /* /*
                        this is a comment
                    */
                    true
            }
            """,
        ])

    def testModules(self):

        self.assertTrueRules([
            'import "tests" rule test { condition: tests.constants.one + 1 == tests.constants.two }',
            'import "tests" rule test { condition: tests.constants.foo == "foo" }',
            'import "tests" rule test { condition: tests.constants.empty == "" }',
            'import "tests" rule test { condition: tests.empty() == "" }',
            'import "tests" rule test { condition: tests.struct_array[1].i == 1 }',
            'import "tests" rule test { condition: tests.struct_array[0].i == 1 or true}',
            'import "tests" rule test { condition: tests.integer_array[0] == 0}',
            'import "tests" rule test { condition: tests.integer_array[1] == 1}',
            'import "tests" rule test { condition: tests.string_array[0] == "foo"}',
            'import "tests" rule test { condition: tests.string_array[2] == "baz"}',
            'import "tests" rule test { condition: tests.string_dict["foo"] == "foo"}',
            'import "tests" rule test { condition: tests.string_dict["bar"] == "bar"}',
            'import "tests" rule test { condition: tests.isum(1,2) == 3}',
            'import "tests" rule test { condition: tests.isum(1,2,3) == 6}',
            'import "tests" rule test { condition: tests.fsum(1.0,2.0) == 3.0}',
            'import "tests" rule test { condition: tests.fsum(1.0,2.0,3.0) == 6.0}',
            'import "tests" rule test { condition: tests.length("dummy") == 5}',
          ])

        self.assertFalseRules([
            'import "tests" rule test { condition: tests.struct_array[0].i == 1 }',
            'import "tests" rule test { condition: tests.isum(1,1) == 3}',
            'import "tests" rule test { condition: tests.fsum(1.0,1.0) == 3.0}',
          ])

    def testIntegerFunctions(self):

        self.assertTrueRules([
            'rule test { condition: uint8(0) == 0xAA}',
            'rule test { condition: uint16(0) == 0xBBAA}',
            'rule test { condition: uint32(0) == 0xDDCCBBAA}',
            'rule test { condition: uint8be(0) == 0xAA}',
            'rule test { condition: uint16be(0) == 0xAABB}',
            'rule test { condition: uint32be(0) == 0xAABBCCDD}',
          ], b'\xAA\xBB\xCC\xDD')

    def testStringIO(self):

        # Python 2/3
        try:
            stream = StringIO.StringIO()
        except:
            stream = io.BytesIO()

        r1 = yara.compile(source='rule test { condition: true }')
        r1.save(stream)

        stream.seek(0)

        r2 = yara.load(stream)
        m = r2.match(data="dummy")

        self.assertTrue(len(m) == 1)



if __name__ == "__main__":
    unittest.main()
