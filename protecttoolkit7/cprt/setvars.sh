#!/bin/sh
# **************************************************************************
# setvars - Setup PTK Environment
# **************************************************************************
#
# NOTE: Do not run this script directly.  Source it or call it from your
#       startup script ( ~/.shrc, ~/.bashrc, etc)
#
#       To globally enable this script, copy or link it to
#       /etc/profile.d/ptkrt.sh or your shell's equivalent
#
# **************************************************************************

if [ "a$(basename -- "$0")" = "asetvars.sh" ]; then
    echo "The PTK setvars script should not be executed directly."
    echo "Source it or call it from a startup script."
fi

export CPROVDIR=/opt/safenet/protecttoolkit7/ptk
export PTKBIN=$CPROVDIR/bin
export PTKLIB=$CPROVDIR/lib
export PTKMAN=$CPROVDIR/man

if [ -x /bin/grep ];
then
  GREPCOMMAND="/bin/grep"
else
  GREPCOMMAND="grep"
fi

if ! echo $PATH | $GREPCOMMAND -q $PTKBIN; then
       export PATH=$PTKBIN:$PATH
fi

if ! echo $LD_LIBRARY_PATH | $GREPCOMMAND -q $PTKLIB; then
       export LD_LIBRARY_PATH=$PTKLIB:$LD_LIBRARY_PATH
fi

if ! echo $MANPATH | $GREPCOMMAND -q $PTKMAN; then
       export MANPATH=$PTKMAN:$MANPATH
fi
