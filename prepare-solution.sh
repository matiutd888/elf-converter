rm -rf mn418323.tar.gz
mv CMakeLists.txt real-CMakeLists.txt
mv CMakeLists-for-solution.txt CMakeLists.txt
tar cf mn418323.tar.gz  README.md CMakeLists.txt src/*.cpp src/*.h 
mv CMakeLists.txt CMakeLists-for-solution.txt
mv real-CMakeLists.txt CMakeLists.txt
