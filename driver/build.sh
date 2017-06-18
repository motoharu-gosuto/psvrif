cd build
make clean
rm CMakeCache.txt
cmake ../
make
make install
cd ..
