Name:		libnet-client
Summary:	Network Client library (Shared library)
Version:	1.1.53
Release:	1
Group:		System/Network
License:	Flora-1.1
Source0:	%{name}-%{version}.tar.gz
BuildRequires:	pkgconfig(dlog)
BuildRequires:	pkgconfig(vconf)
BuildRequires:	pkgconfig(gio-2.0)
BuildRequires:	pkgconfig(glib-2.0)
BuildRequires:	pkgconfig(gthread-2.0)

%description
Network Client library (Shared library)

%package devel
Summary:	Network Client library (Development)
Group:		Development/Library
Requires:	%{name} = %{version}-%{release}

%description devel
Network Client library (Development)

%prep
%setup -q


%build
%if 0%{?model_build_feature_network_dsds} == 1
export DUALSIM_CFLAGS+=" -DTIZEN_DUALSIM_ENABLE"
%endif

%if "%{profile}" == "wearable"
export WEARABLE_CFLAGS+=" -DTIZEN_WEARABLE"
%endif

%if "%{profile}" == "tv"
	export TIZEN_TV_CFLAGS+=" -DTIZEN_TV"
%endif

./autogen.sh
./configure --prefix=/usr --libdir=%{_libdir}

make %{?_smp_mflags}


%install
%make_install

#License
mkdir -p %{buildroot}%{_datadir}/license
cp LICENSE %{buildroot}%{_datadir}/license/libnet-client

cd test
cp -rf %{buildroot}%{_libdir}/ ./
./build.sh
cd ..

%files
%manifest libnet-client.manifest
%{_libdir}/libnetwork.so
%{_libdir}/libnetwork.so.0
%attr(644,-,-) %{_libdir}/libnetwork.so.0.0.0
%{_datadir}/license/libnet-client

%files devel
%{_includedir}/network/*.h
%{_libdir}/pkgconfig/network.pc
