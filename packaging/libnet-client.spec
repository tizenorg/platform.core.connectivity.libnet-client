#sbs-git:slp/pkgs/l/libnet-client

Name:       libnet-client
Summary:    Network (ConnMan) Client library (Shared Library)
Version:    0.1.63
Release:    1
Group:      System/Network
License:    Samsung Proprietary License
Source0:    %{name}-%{version}.tar.gz
BuildRequires:  cmake
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(dbus-glib-1)
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)

%description
Network (ConnMan) Client library (Shared Library)

%package devel
Summary:    Network (ConnMan) Client library (Development)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Network (ConnMan) Client library (Development)

%prep
%setup -q

./autogen.sh

%build

./configure --prefix=/usr

make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
%make_install

%files
%defattr(-,root,root,-)
%{_libdir}/libnetwork.so
%{_libdir}/libnetwork.so.0
%attr(644,-,-) %{_libdir}/libnetwork.so.0.0.0

%files devel
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/network.pc
