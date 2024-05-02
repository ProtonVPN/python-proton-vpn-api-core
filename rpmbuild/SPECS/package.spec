%define unmangled_name proton-vpn-api-core
%define version 0.24.3
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
BuildRequires: python3-proton-vpn-logger
BuildRequires: python3-proton-vpn-killswitch
BuildRequires: python3-setuptools
BuildRequires: python3-distro
BuildRequires: python3-sentry-sdk
BuildRequires: python3-pynacl

Requires: python3-proton-core
Requires: python3-proton-vpn-connection
Requires: python3-proton-vpn-logger
Requires: python3-proton-vpn-killswitch
Requires: python3-distro
Requires: python3-sentry-sdk
Requires: python3-pynacl

Conflicts: proton-vpn-gtk-app < 4.3.1~rc1
Obsoletes: python3-proton-vpn-session

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
* Fri May 03 2024 Luke Titley <luke.titley@proton.ch> 0.24.3
- Set the sentry user id based on a hash of /etc/machine-id

* Thu May 02 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.24.2
- Fix deprecation warning when calculatin WireGuard certificate validity period.

* Tue Apr 30 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.24.1
- Fix error saving cache file when parent directory does not exist

* Tue Apr 30 2024 Luke Titley <luke.titley@proton.ch> 0.24.0
- Only initialize sentry on first enable.
- Forward SSL_CERT_FILE environment variable to sentry.

* Mon Apr 23 2024 Luke Titley <luke.titley@proton.ch> 0.23.1
- Added missing pip dependencies.

* Mon Apr 22 2024 Luke Titley <luke.titley@proton.ch> 0.23.0
- Merged proton-vpn-api-session package into this one.

* Thu Apr 18 2024 Luke Titley <luke.titley@proton.ch> 0.22.5
- Pass requested features through to session login and two factor submit.

* Tue Apr 16 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.22.4
- Provide method to update certificate.

* Thu Apr 11 2024 Luke Titley <luke.titley@proton.ch> 0.22.3
- Ensure that crash reporting state is preserved between restarts

* Wed Apr 10 2024 Luke Titley <luke.titley@proton.ch> 0.22.2
- Explicitly state the sentry integrations we want. Dont include the ExceptHookIntegration

* Wed Apr 10 2024 Luke Titley <luke.titley@proton.ch> 0.22.1
- Change url for sentry, dont send server_name, use older sentry api

* Fri Apr 5 2024 Luke Titley <luke.titley@proton.ch> 0.22.0
- Add mechanism to send errors anonymously to sentry.

* Thu Apr 4 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.21.2
- Return list of protocol plugins for a specific backend instead of returning a list of protocols names

* Fri Mar 1 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.21.1
- Add WireGuard ports

* Fri Feb 16 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.21.0
- Apply kill switch setting immediately

* Wed Feb 14 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.20.4
- Initialize VPNConnector with settings

* Wed Dec 13 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.20.3
- Make VPN connection API async

* Wed Nov 08 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.20.2
- Make API async and avoid thread-safety issues in asyncio code
- Move bug report submission to proton-vpn-session

* Tue Oct 10 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.20.1
- Update dependencies

* Fri Sep 15 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.20.0
- Expose properties which allow to access account related data

* Mon Sep 04 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.19.0
- Add kill switch to settings and add dependency for base kill switch package

* Wed Jul 19 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.18.0
- Rename setting random_nat to moderate_nat to conform to API specs

* Fri Jul 07 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.17.0
- Enable NetShield by default on paid plans

* Wed Jul 05 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.16.0
- Add protocol entry to settings

* Mon Jul 03 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.15.0
- Implement save method for settings

* Tue Jun 20 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.14.0
- Remove split tunneling and ipv6 options from settings

* Wed Jun 14 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.13.0
- Expose server loads update

* Thu Jun 08 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.12.1
- Fix settings defaults

* Tue Jun 06 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.12.0
- Pass X-PM-netzone header when retrieving /vpn/logicals and /vpn/loads

* Fri Jun 02 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.11.0
- Ensure general settings are taken into account when establishing a vpn connection

* Fri May 26 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.10.3
- Specify exit IP of physical server

* Mon Apr 24 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.10.2
- Fix issue where multiple attachments were overwritten when submitting a bug report

* Mon Apr 03 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.10.1
- Adapt to VPN connection refactoring

* Tue Feb 28 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.10.0
- Implement new appversion format

* Tue Feb 14 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.9.0
- Use standardized paths for cache and settings

* Tue Feb 07 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.8.2
- Do not raise exception during logout if there is an active connection

* Fri Jan 20 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.8.1
- Send bug report using proton-core

* Tue Jan 17 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.8.0
- Feature: Report a bug

* Fri Jan 13 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.7.0
- Move get_vpn_server to VPNConnectionHolder

* Thu Jan 12 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.6.0
- Expose methods to load api data from the cache stored in disk

* Mon Dec 05 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.5.0
- Persist VPN server to disk

* Tue Nov 29 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.4.0
- Decoupled VPNServers and ClientConfig
- All methods that return a server will now return a LogicalServer instead of VPNServer

* Fri Nov 25 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.3.1
- Check if there is an active connection before logging out

* Thu Nov 17 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.3.0
- Fetch and cache clientconfig data from API

* Tue Nov 15 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.7
- Allow cancelling a VPN connection before it is established

* Tue Nov 15 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.6
- Check connection status before connecting/disconnecting

* Fri Nov 11 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.5
- Add Proton VPN logging library

* Wed Nov 09 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.4
- Lazy load the currently active Proton VPN connection, if existing

* Fri Nov 8 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.3
- Ensure that appversion and user-agent are passed when making API calls

* Fri Nov 4 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.2
- Ensure that before establishing a new connection, the previous connection is disconnected, if there is one

* Mon Sep 26 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.1
- Delete cache at logout

* Thu Sep 22 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.0
- Add method to obtain the user's tier

* Fri Sep 20 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.0
- Add logging

* Thu Sep 19 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.0.4
- Cache VPN connection

* Thu Sep 8 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.0.3
- VPN servers retrieval

* Wed Jun 1 2022 Proton Technologies AG <opensource@proton.me> 0.0.2
- First RPM release
