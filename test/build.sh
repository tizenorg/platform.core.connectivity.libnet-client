#!/bin/sh

rm -f network_client

gcc -Wall -g -O2 -o ./network_client ./main.c `pkg-config glib-2.0 dbus-glib-1 gthread-2.0 --cflags --libs` -I../include/common -I../include/profile -I../include/wifi -L./lib/ -lnetwork

