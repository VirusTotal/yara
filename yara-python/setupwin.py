from distutils.core import setup, Extension

                           
setup(  name = "yara-python",
        version = "1.5",
        author = "Victor M. Alvarez",
        author_email = "victor.alvarez@virustotal.com",
        ext_modules = [ Extension(
                                    name='yara', 
                                    sources=['yara-python.c'],
                                    include_dirs=['../windows/include', '../libyara'],
                                    extra_objects=['../windows/yara/Release/libyara.lib','../windows/lib/pcre.lib']
                                    )])
     
 
                                  