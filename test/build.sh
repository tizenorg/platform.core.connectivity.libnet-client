#!/bin/sh

rm -f network_client

gcc -Wall -g -O2 -o ./network_client ./main.c `pkg-config dbus-1 glib-2.0 dbus-glib-1 network --cflags --libs` 

