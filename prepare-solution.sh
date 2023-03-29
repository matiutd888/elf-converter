rm -rf mn418323.zip
mv CMakeLists.txt real-CMakeLists.txt
mv CMakeLists-for-solution.txt CMakeLists.txt
zip -r mn418323.zip  README.md CMakeLists.txt src/*.cpp src/*.h --exclude src/build
mv CMakeLists.txt CMakeLists-for-solution.txt
mv real-CMakeLists.txt CMakeLists.txt