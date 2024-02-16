#!/bin/sh
rm -rf build
mkdir build
cd src
ls ../lib
javac -cp ../lib/*:. -d ../build Main.java
if test "$?" -ne 0; then
	echo "Compilation failed!"
	exit 1
fi
cd ..
# explode lib
cd build
find ../lib -name \*.jar -exec unzip {} \;
cd ..
jar -c -f webserver.jar -e Main -C build . -C resource .
