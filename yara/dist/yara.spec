##
## Copyright (c) 2007-2015. The YARA Authors. All Rights Reserved.
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
## http://www.apache.org/licenses/LICENSE-2.0
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##

Name:           yara
Version:        3.2.0
Release:        1
License:        Apache License 2.0
Summary:        A malware identification and classification tool
Url:            http://plusvic.github.io/yara/
Group:          System/Filesystems
Source:         yara-%{version}.tar.gz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  autoconf automake libtool

%description
YARA is a tool aimed at helping malware researchers to identify and classify
malware samples. With YARA you can create descriptions of malware families
based on textual or binary patterns contained on samples of those families.

%package -n libyara
Summary:        Library to support the yara malware identification tool
Group:          System/Libraries

%description -n libyara
YARA is a tool aimed at helping malware researchers to identify and classify
malware samples. With YARA you can create descriptions of malware families
based on textual or binary patterns contained on samples of those families.

%package -n yara-devel
Summary:        Development files to support the yara malware identification tool
Group:          Development/Libraries/C and C++
Requires:       libyara = %{version}-%{release}

%description -n yara-devel
YARA is a tool aimed at helping malware researchers to identify and classify
malware samples. With YARA you can create descriptions of malware families
based on textual or binary patterns contained on samples of those families.

%prep
%setup -q

%build
./bootstrap.sh
./configure
make

%install
make install DESTDIR=%{buildroot} bindir=%{_bindir} libdir=%{_libdir} includedir=%{_includedir} mandir=%{_mandir} INSTALL="install -p"

%post -n libyara -p /sbin/ldconfig

%postun -n libyara -p /sbin/ldconfig

%files
%defattr(-,root,root)
%{_bindir}/yara
%{_bindir}/yarac
%{_mandir}/man1/*

%files -n libyara
%defattr(-,root,root)
%{_libdir}/libyara.so*
%{_libdir}/pkgconfig/yara.pc

%files -n yara-devel
%defattr(-,root,root)
%{_includedir}/yara.h
%{_includedir}/yara/*
%{_libdir}/libyara.a
%{_libdir}/libyara.la


%changelog
* Sat Jan 25 2015 Domingo Kiser <domingo.kiser@gmail.com> 3.2.0-1
  Initial Creation.
