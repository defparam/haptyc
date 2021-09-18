#!/bin/bash

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd "$SCRIPT_DIR/haptyc/PayloadStrings"
ls -a *.pay | sort > manifest.txt
cd $SCRIPT_DIR

TMPDIR=$(mktemp -d)
mkdir -p $TMPDIR/Lib
cp -rf ./haptyc $TMPDIR/Lib
cd $TMPDIR

echo "[+] Haptyc Installer by defparam"
echo "[+]"

if [ $# -eq 0 ]
then
    echo "[+] Usage: ./install.sh <path>" 
    echo "[+] Error: you must provide a directory tree that contains turbo-intruder-all.jar"
else
    echo "[+] Searching for turbo-intruder-all.jar inside $1 ..."
    echo "[+]"
	RES=$(find $1 -type f -name turbo-intruder-all.jar)
	
	if [ ! -z "$RES" ]; then
		echo "[+] Installing into: $RES"
		EXISTS=$(unzip -l $RES | grep "Lib/haptyc")
		if [ ! -z "$EXISTS" ]; then
			zip -qd "$RES" ./Lib/haptyc/* ./Lib/haptyc; &>/dev/null
		fi
		zip -qru "$RES" ./Lib/haptyc &>/dev/null
	else
		echo "[+] Error: could not find turbo-intruder-all.jar under $1"
	fi
    echo "[+] Done!"
fi

cd /
rm -rf $TMPDIR
