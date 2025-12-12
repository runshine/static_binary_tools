#!/bin/bash

ARCH="$(uname -m)"

if [ "$ARCH" = "armv7l" ];then
  if [ "x$(cat /proc/self/maps|grep gnueabihf)" != "x" ];then
    ARCH="armhf"
  else
    ARCH="armel"
  fi
fi
export ARCH