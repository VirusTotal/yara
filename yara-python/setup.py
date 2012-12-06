from distutils.core import setup, Extension
                           
setup(  name = "yara-python",
        version = "1.7",
        author = "Victor M. Alvarez",
        author_email = "vmalvarez@virustotal.com",
        url = 'http://yara-project.googlecode.com',
        platforms = ['any'],
        ext_modules = [ Extension(
                                    name='yara', 
                                    sources=['yara-python.c'],
                                    libraries=['yara','pcre'],
                                    include_dirs=['/usr/local/include']
                                    )])
     
 
                                  
