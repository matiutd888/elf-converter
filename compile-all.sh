cd build
make clean
make
cd ../bartek-test
cp ../build/converter .
make clean
make
cd ../z1_test/
cp ../build/converter .
make clean
make
cd ../examples/polecenie
cp ../../build/converter
make clean
make

