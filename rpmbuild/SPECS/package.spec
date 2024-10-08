
%define unmangled_name proton-vpn-api-core
%define version 0.36.2
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
BuildRequires: python3-setuptools
BuildRequires: python3-distro
BuildRequires: python3-sentry-sdk
BuildRequires: python3-pynacl
BuildRequires: python3-jinja2

Requires: python3-proton-core
Requires: python3-distro
Requires: python3-sentry-sdk
Requires: python3-pynacl
Requires: python3-jinja2

Conflicts: proton-vpn-gtk-app < 4.4.2~rc5
Conflicts: python3-proton-vpn-network-manager < 0.9.2

Obsoletes: python3-proton-vpn-session
Obsoletes: python3-proton-vpn-connection
Obsoletes: python3-proton-vpn-killswitch
Obsoletes: python3-proton-vpn-logger

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
* Tue Oct 08 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.36.2
- Fix certificate expired regression

* Fri Oct 04 2024 Luke Titley <luke.titley@proton.ch> 0.36.1
- Enable certificate based authentication for openvpn.

* Thu Oct 03 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.35.8
- Improve logic on when to update location details.
- Add tests.

* Wed Oct 02 2024 Luke Titley <luke.titley@proton.ch> 0.35.7
- Use a 'before_send' callback in sentry to sanitize events in sentry

* Wed Oct 02 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.35.6
- Update location object after successfully connecting to VPN server via local agent.

* Fri Sep 27 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.35.5
- Fix regression sending errors to sentry.

* Tue Sep 24 2024 Luke Titley <luke.titley@proton.ch> 0.35.4
- Fix to rpm package.spec, added accidentally removed Obsoletes statement.

* Tue Sep 24 2024 Luke Titley <luke.titley@proton.ch> 0.35.3
- Send all errors to sentry, but swallow api errors.

* Mon Sep 23 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.35.2
- Merge logger package into this one.

* Mon Sep 23 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.35.1
- Fix refregresion (logout user on 401 API error).

* Mon Sep 09 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.35.0
- Catch and send LA errors to sentry.

* Fri Sep 13 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.34.0
- Import refreshers from app.

* Fri Sep 06 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.33.12
- Ensure there is a way to disable IPv6.

* Mon Sep 02 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.33.11
- Change IPv6 default value and move out of the features dict.

* Fri Aug 30 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.33.10
- Properly configure OpenVPN with IPv6 value.

* Thu Aug 29 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.33.9
- Pass IPv6 value.

* Wed Aug 28 2024 Luke Titley <luke.titley@proton.ch> 0.33.8
- Put changes to fetching with timestamp (If-Modified-Since), behind a feature flag.

* Wed Aug 28 2024 Luke Titley <luke.titley@proton.ch> 0.33.7
- Fixes support for 'If-Modified-Since', expiration times.

* Tue Aug 27 2024 Luke Titley <luke.titley@proton.ch> 0.33.6
- Fixes support for 'If-Modified-Since' header in server list requests.

* Mon Aug 26 2024 Luke Titley <luke.titley@proton.ch> 0.33.5
- This adds support for 'If-Modified-Since' header in server list requests.

* Thu Aug 22 2024 Luke Titley <luke.titley@proton.ch> 0.33.4
- Make sure features cant be request after connection as well.

* Thu Aug 22 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.33.3
- Expose property in VPNConnection to know if features can be applied on active connections.

* Wed Aug 21 2024 Luke Titley <luke.titley@proton.ch> 0.33.2
- Tier 0 level users can't control the features they have. So don't send any feature requests for them.

* Wed Aug 21 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.33.1
- Fix crash after logout

* Tue Aug 20 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.33.0
- Get rid of VPNConnectorWrapper.

* Tue Aug 20 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.32.2
- Enable wireguard feature flag by default.

* Mon Aug 12 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.32.1
- Handle UnicodeDecodeError when loading persisted VPN connection.

* Mon Aug 12 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.32.0
- Update connection features via local agent if available.

* Thu Aug 08 2024 Luke Titley <luke.titley@proton.ch> 0.31.0
- Disconnect and notify the user when the maximum number of sessions is reached.

* Fri Jul 26 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.30.0
- Handle ExpiredCertificate events.

* Wed Jul 17 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.29.4
- Update default feature flags and update feature flags interface.

* Wed Jul 17 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.29.3
- Update credentials in the background

* Fri Jul 12 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.29.2
- Fix crash initializing VPN connector.

* Fri Jul 12 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.29.1
- Update VPN credentials when an active VPN connection is found at startup.

* Wed Jul 10 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.29.0
- Merge connection and kill switch packages into this one.

* Thu Jul 11 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.28.1
- Improve testing to capture when default value is being passed.

* Wed Jul 10 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.28.0
- Implement and expose feature flags.

* Tue Jul 09 2024 Luke Titley <luke.titley@proton.ch> 0.27.3
- Move local agent management into wireguard backend.

* Tue Jul 09 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.27.2
- Send CPU architecture following semver's specs.

* Tue Jul 02 2024 Luke Titley <luke.titley@proton.ch> 0.27.1
- Switched over to async local agent api.

* Mon Jul 01 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.27.0
- Attempt to use external local agent package, otherwise fallback to existent one.

* Mon Jun 24 2024 Luke Titley <luke.titley@proton.ch> 0.26.4
- Add the architecture in the appversion field for ProtonSSO.

* Mon Jun 17 2024 Luke Titley <luke.titley@proton.ch> 0.26.3
- Switch over to automatically generated changelogs for debian and rpm.

* Mon Jun 10 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.26.2
- Fix sentry error sanitization crash.

* Tue Jun 04 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.26.1
- Fix certificate duration regression.

* Thu May 30 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.26.0
- Send wireguard certificate to server via local agent.

* Fri May 24 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.25.1
- Increase certificate duration.

* Thu May 23 2024 Luke Titley <luke.titley@proton.ch> 0.25.0
- Refactor of Settings to ensure settings are only saved when they are changed.

* Wed May 08 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.24.5
- Stop raising exceptions when getting wireguard certificate and it is expired.

* Tue May 07 2024 Luke Titley <luke.titley@proton.ch> 0.24.4
- Filter OSError not just FileNotFound error in sentry.

* Fri May 03 2024 Luke Titley <luke.titley@proton.ch> 0.24.3
- Set the sentry user id based on a hash of /etc/machine-id.

* Thu May 02 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.24.2
- Fix deprecation warning when calculatin WireGuard certificate validity period.

* Tue Apr 30 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.24.1
- Fix error saving cache file when parent directory does not exist.

* Tue Apr 30 2024 Luke Titley <luke.titley@proton.ch> 0.24.0
- Only initialize sentry on first enable.
- Forward SSL_CERT_FILE environment variable to sentry.

* Tue Apr 23 2024 Luke Titley <luke.titley@proton.ch> 0.23.1
- Added missing pip dependencies.

* Mon Apr 22 2024 Luke Titley <luke.titley@proton.ch> 0.23.0
- Merged proton-vpn-api-session package into this one.

* Thu Apr 18 2024 Luke Titley <luke.titley@proton.ch> 0.22.5
- Pass requested features through to session login and two factor submit.

* Tue Apr 16 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.22.4
- Provide method to update certificate.

* Wed Apr 10 2024 Luke Titley <luke.titley@proton.ch> 0.22.3
- Ensure that crash reporting state is preserved between restarts.

* Wed Apr 10 2024 Luke Titley <luke.titley@proton.ch> 0.22.2
- Explicitly state the sentry integrations we want. Dont include the ExceptHookIntegration.

* Wed Apr 10 2024 Luke Titley <luke.titley@proton.ch> 0.22.1
- Change url for sentry, dont send server_name, use older sentry api.

* Fri Apr 05 2024 Luke Titley <luke.titley@proton.ch> 0.22.0
- Add mechanism to send errors anonymously to sentry.

* Thu Apr 04 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.21.2
- Return list of protocol plugins for a specific backend instead of returning a list of protocols names.

* Fri Mar 01 2024 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.21.1
- Add WireGuard ports.

* Fri Feb 16 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.21.0
- Apply kill switch setting immediately.

* Wed Feb 14 2024 Josep Llaneras <josep.llaneras@proton.ch> 0.20.4
- Initialize VPNConnector with settings.

* Wed Dec 13 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.20.3
- Make VPN connection API async.

* Wed Nov 08 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.20.2
- Make API async and avoid thread-safety issues in asyncio code.
- Move bug report submission to proton-vpn-session.

* Tue Oct 10 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.20.1
- Update dependencies.

* Fri Sep 15 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.20.0
- Expose properties which allow to access account related data.

* Mon Sep 04 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.19.0
- Add kill switch to settings and add dependency for base kill switch package.

* Wed Jul 19 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.18.0
- Rename setting random_nat to moderate_nat to conform to API specs.

* Fri Jul 07 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.17.0
- Enable NetShield by default on paid plans.

* Wed Jul 05 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.16.0
- Add protocol entry to settings.

* Mon Jul 03 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.15.0
- Implement save method for settings.

* Tue Jun 20 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.14.0
- Remove split tunneling and ipv6 options from settings.

* Wed Jun 14 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.13.0
- Expose server loads update.

* Thu Jun 08 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.12.1
- Fix settings defaults.

* Tue Jun 06 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.12.0
- Pass X-PM-netzone header when retrieving /vpn/logicals and /vpn/loads.

* Fri Jun 02 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.11.0
- Ensure general settings are taken into account when establishing a vpn connection.

* Fri May 26 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.10.3
- Specify exit IP of physical server.

* Mon Apr 24 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.10.2
- Fix issue where multiple attachments were overwritten when submitting a bug report.

* Mon Apr 03 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.10.1
- Adapt to VPN connection refactoring.

* Tue Feb 28 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.10.0
- Implement new appversion format.

* Tue Feb 14 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.9.0
- Use standardized paths for cache and settings.

* Tue Feb 07 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.8.2
- Do not raise exception during logout if there is an active connection.

* Fri Jan 20 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.8.1
- Send bug report using proton-core.

* Tue Jan 17 2023 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.8.0
- Feature: Report a bug.

* Fri Jan 13 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.7.0
- Move get_vpn_server to VPNConnectionHolder.

* Thu Jan 12 2023 Josep Llaneras <josep.llaneras@proton.ch> 0.6.0
- Expose methods to load api data from the cache stored in disk.

* Mon Dec 05 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.5.0
- Persist VPN server to disk.

* Tue Nov 29 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.4.0
- Decoupled VPNServers and ClientConfig.
- All methods that return a server will now return a LogicalServer instead of VPNServer.

* Fri Nov 25 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.3.1
- Check if there is an active connection before logging out.

* Thu Nov 17 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.3.0
- Fetch and cache clientconfig data from API.

* Tue Nov 15 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.7
- Allow cancelling a VPN connection before it is established.

* Tue Nov 15 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.6
- Check connection status before connecting/disconnecting.

* Fri Nov 11 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.5
- Add Proton VPN logging library.

* Wed Nov 09 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.4
- Lazy load the currently active Proton VPN connection, if existing.

* Tue Nov 08 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.3
- Ensure that appversion and user-agent are passed when making API calls.

* Fri Nov 04 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.2.2
- Ensure that before establishing a new connection, the previous connection is disconnected, if there is one.

* Mon Sep 26 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.1
- Delete cache at logout.

* Thu Sep 22 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.2.0
- Add method to obtain the user's tier.

* Tue Sep 20 2022 Alexandru Cheltuitor <alexandru.cheltuitor@proton.ch> 0.1.0
- Add logging.

* Mon Sep 19 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.0.4
- Cache VPN connection.

* Thu Sep 08 2022 Josep Llaneras <josep.llaneras@proton.ch> 0.0.3
- VPN servers retrieval.

* Wed May 25 2022 Proton Technologies AG <opensource@proton.me> 0.0.2
- Fixing and simplifying 2FA logic.

* Mon Mar 14 2022 Proton Technologies AG <opensource@proton.me> 0.0.1
- First release.

