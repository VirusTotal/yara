%define name yara-python
%define version 3.2.0
%define unmangled_version 3.2.0
%define release 1

Summary: Python bindings for YARA malware research tool
Name: %{name}
Version: %{version}
Release: %{release}
Source0: %{name}-%{unmangled_version}.tar.gz
License: Apache License 2.0
Group: Development/Libraries
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot
Prefix: %{_prefix}
Vendor: Victor M. Alvarez <plusvic@gmail.com;vmalvarez@virustotal.com>
BuildRequires: gcc python-devel
BuildRequires: libyara-devel

%description
YARA is a tool aimed at (but not limited to) helpingmalware researchers to identify and classify malwaresamples. With YARA you can create descriptions of malware families (or whatever you want to describe)based on textual or binary patterns.

%prep
%setup -n %{name}-%{unmangled_version}

%build
env CFLAGS="$RPM_OPT_FLAGS" python setup.py build

%install
python setup.py install -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES

%clean
rm -rf $RPM_BUILD_ROOT

%files -f INSTALLED_FILES
%defattr(-,root,root)
