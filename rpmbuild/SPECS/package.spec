%define unmangled_name proton-vpn-api-core
%define version 0.0.2
%define release 1

Prefix: %{_prefix}

Name: python3-%{unmangled_name}
Version: %{version}
Release: %{release}%{?dist}
Summary: %{unmangled_name} library

Group: ProtonVPN
License: GPLv3
Vendor: Proton Technologies AG <opensource@proton.me>
URL: https://github.com/ProtonVPN/%{unmangled_name}
Source0: %{unmangled_name}-%{version}.tar.gz
BuildArch: noarch
BuildRoot: %{_tmppath}/%{unmangled_name}-%{version}-%{release}-buildroot

BuildRequires: python3-proton-core
BuildRequires: python3-proton-vpn-connection
BuildRequires: python3-proton-vpn-session
BuildRequires: python3-proton-vpn-servers
BuildRequires: python3-setuptools

Requires: python3-proton-core
Requires: python3-proton-vpn-connection
Requires: python3-proton-vpn-session
Requires: python3-proton-vpn-servers

%{?python_disable_dependency_generator}

%description
Package %{unmangled_name} library.


%prep
%setup -n %{unmangled_name}-%{version} -n %{unmangled_name}-%{version}

%build
python3 setup.py build

%install
python3 setup.py install --single-version-externally-managed -O1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES


%files -f INSTALLED_FILES
%{python3_sitelib}/proton/
%{python3_sitelib}/proton_vpn_api_core-%{version}*.egg-info/
%defattr(-,root,root)

%changelog
* Wed Jun 1 2022 Proton Technologies AG <opensource@proton.me> 0.0.2
- First RPM release
