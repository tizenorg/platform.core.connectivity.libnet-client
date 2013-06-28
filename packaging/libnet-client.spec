Name:       libnet-client
Summary:    Network Client library (Shared library)
Version:    0.1.77_37
Release:    1
Group:      System/Network
License:    Flora License
Source0:    %{name}-%{version}.tar.gz
Source1001: 	libnet-client.manifest
URL:        https://review.tizen.org/git/?p=framework/connectivity/libnet-client.git;a=summary
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig
BuildRequires:  cmake
BuildRequires:  pkgconfig(dlog)
BuildRequires:  pkgconfig(vconf)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(gthread-2.0)
BuildRequires:	pkgconfig(dbus-glib-1)

%description
Network Client library (Shared library)

%package devel
Summary:    Network Client library (Development)
Group:      Development/Libraries
Requires:   %{name} = %{version}-%{release}

%description devel
Network Client library (Development)

%prep
%setup -q
cp %{SOURCE1001} .


%build
%autogen.sh
%configure

make %{?_smp_mflags}


%install
%make_install

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE.Flora %{buildroot}%{_datadir}/license/libnet-client

#Make test app
cd test
mkdir ./lib
cp -rf %{buildroot}%{_libdir}/* ./lib/
./build.sh
cd ..

%post -p /sbin/ldconfig

%postun -p /sbin/ldconfig

%files
%manifest %{name}.manifest
%{_libdir}/libnetwork.so
%{_libdir}/libnetwork.so.0
%attr(644,-,-) %{_libdir}/libnetwork.so.0.0.0
%{_datadir}/license/libnet-client

%files devel
%manifest %{name}.manifest
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/network.pc
