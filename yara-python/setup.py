#
# Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.
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

from distutils.core import setup, Extension

setup(name='yara-python',
      version='3.3.0',
      author='Victor M. Alvarez',
      author_email='plusvic@gmail.com;vmalvarez@virustotal.com',
      ext_modules=[Extension(
        name='yara',
        sources=['yara-python.c'],
        libraries=['yara'],
        include_dirs=['../libyara/include'],
        library_dirs=['../libyara/.libs'],
        extra_compile_args=['-std=gnu99']
    )])
