import tempfile
import binascii
import os
import unittest
import yara


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


class TestYara(unittest.TestCase):

    def assertTrueRules(self, rules, data='dummy'):

        for r in rules:
            r = yara.compile(source=r)
            self.assertTrue(r.match(data=data))

    def assertFalseRules(self, rules, data='dummy'):

        for r in rules:
            r = yara.compile(source=r)
            self.assertFalse(r.match(data=data))

    def testBooleanOperators(self):

        self.assertTrueRules([
            'rule test { condition: true }',
            'rule test { condition: true or false }',
            'rule test { condition: true and true }'
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
            'rule test { condition: 1 == 1 }'
        ])

        self.assertFalseRules([
            'rule test { condition: 1 != 1}',
            'rule test { condition: 2 > 3}',
        ])

    def testArithmeticOperators(self):

        self.assertTrueRules([
            'rule test { condition: (1 + 1) * 2 == (9 - 1) \ 2 }',
            'rule test { condition: 5 % 2 == 1 }'
        ])

    def testBitwiseOperators(self):

        self.assertTrueRules([
            'rule test { condition: 0x55 | 0xAA == 0xFF }',
            'rule test { condition: ~0xAA ^ 0x5A & 0xFF == 0x0F }',
            'rule test { condition: ~0x55 & 0xFF == 0xAA }',
            'rule test { condition: 8 >> 2 == 2 }',
            'rule test { condition: 1 << 3 == 8 }'
        ])

    def testStrings(self):

        self.assertTrueRules([
            'rule test { strings: $a = "a" condition: $a }',
            'rule test { strings: $a = "abc" condition: $a }',
            'rule test { strings: $a = "xyz" condition: $a }',
            'rule test { strings: $a = "abc" wide nocase fullword condition: $a }',
            'rule test { strings: $a = "aBc" nocase  condition: $a }',
            'rule test { strings: $a = "abc" fullword condition: $a }',
        ], "---- abc ---- A\x00B\x00C\x00 ---- xyz")

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
        ], PE32_FILE)

    def testCount(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" condition: #a == 2 }',
        ], 'mississippi')

    def testAt(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" condition: $a at 2 and $a at 5 }',
        ], 'mississippi')

    def testOf(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: any of them }',
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: 1 of them }',
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: 2 of them }'
        ], 'mississipi')

        self.assertFalseRules([
            'rule test { strings: $a = "ssi" $b = "mis" $c = "oops" condition: all of them }'
        ], 'mississipi')

    def testForAll(self):

        self.assertTrueRules([
            'rule test { strings: $a = "ssi" condition: for all i in (1..#a) : (@a[i] >= 2 and @a[i] <= 5) }'
        ], 'mississipi')

    def testRE(self):

        self.assertTrueRules([
            'rule test { strings: $a = /ssi/ condition: $a }',
            'rule test { strings: $a = /ssi(s|p)/ condition: $a }',
            'rule test { strings: $a = /ssim*/ condition: $a }',
            'rule test { strings: $a = /ssa?/ condition: $a }',
            'rule test { strings: $a = /Miss/ nocase condition: $a }',
            'rule test { strings: $a = /(Mi|ssi)ssippi/ nocase condition: $a }',
            'rule test { strings: $a = /ppi\tmi/ condition: $a }',
            'rule test { strings: $a = /ppi\.mi/ condition: $a }',
            'rule test { strings: $a = /^mississippi/ fullword condition: $a }',
        ], 'mississippi\tmississippi.mississippi')

        self.assertFalseRules([
            'rule test { strings: $a = /^ssi/ condition: $a }',
            'rule test { strings: $a = /ssi$/ condition: $a }',
            'rule test { strings: $a = /ssissi$/ fullword condition: $a }'
        ], 'mississippi')

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

        r = yara.compile(source='rule test { condition: ext_bool }', externals={'ext_bool': True})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_bool }', externals={'ext_bool': False})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str contains "ssi" }', externals={'ext_str': 'mississippi'})
        self.assertTrue(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /foo/ }', externals={'ext_str': ''})
        self.assertFalse(r.match(data='dummy'))

        r = yara.compile(source='rule test { condition: ext_str matches /ssi(s|p)/ }', externals={'ext_str': 'mississippi'})
        self.assertTrue(r.match(data='dummy'))

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


if __name__ == "__main__":
    unittest.main()
