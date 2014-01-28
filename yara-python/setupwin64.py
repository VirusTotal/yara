from distutils.core import setup, Extension

setup(name='yara-python',
      version='2.0',
      author='Victor M. Alvarez',
      author_email='vmalvarez@virustotal.com',
      ext_modules=[Extension(
        name='yara',
        sources=['yara-python.c'],
        include_dirs=['../windows/include', '../libyara'],
	   define_macros=[('WIN32', None)],
        extra_objects=[
          '../windows/libyara/Release/libyara64.lib']
        )])
