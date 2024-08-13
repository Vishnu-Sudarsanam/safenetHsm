#!/bin/sh
#
# This file is provided as part of the SafeNet Protect Toolkit FM SDK.
#
# (c) Copyright 2000-2014 SafeNet, Inc. All rights reserved.
# This file is protected by laws protecting trade secrets and confidential
# information, as well as copyright laws and international treaties.
#


NAME=hsmstate
JAR=$LD_LIBRARY_PATH/jhsm.jar

echo ============================================
echo This sample illustrates the $NAME command
echo implemented via JHSM library.
echo ============================================

$JDK/bin/javac -classpath $JAR $NAME.java 
$JDK/bin/java  -classpath $JAR:`pwd` $NAME $1 $2 $3 $4 $5
