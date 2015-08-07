#!/bin/sh
# How to build this test app
# 1. insert below contents in end of spec file (install)
#    cd test
#    cp -rf %{buildroot}/usr/lib/ ./
#    ./build.sh
#    cd ..
# 2. find network_client in your build repository in build system


#rm -f network_client

#gcc -Wall -g -O2 -o ./network_client ./main.c `pkg-config gio-2.0 glib-2.0 gthread-2.0 --cflags --libs` -I../include/common -I../include/profile -I../include/wifi -L./lib/ -lnetwork
