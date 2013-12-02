from distutils.core import setup, Extension

setup(  name = "yara-python",
        version = "1.7.2",
        author = "Victor M. Alvarez",
        author_email = "vmalvarez@virustotal.com",
        url = 'http://plusvic.github.io/yara/',
        platforms = ['any'],
        ext_modules = [ Extension(
                                    name='yara',
                                    sources=['yara-python.c'],
                                    libraries=['yara','pcre'],
                                    include_dirs=['/usr/local/include']
                                    )])



