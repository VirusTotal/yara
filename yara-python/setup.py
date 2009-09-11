from distutils.core import setup, Extension

                           
setup(name = "yara-python",
        version = "1.2.1",
        author = "Victor M. Alvarez",
        author_email = "plusvic@gmail.com",
        url = 'http://yara.googlecode.com',
        platforms = ['any'],
        ext_modules = [ Extension(
                                    name='yara', 
                                    sources=['yara-python.c'],
                                    libraries=['yara','pcre'],
                                    include_dirs=['/usr/local/include']
                                    )])
     
 
                                  