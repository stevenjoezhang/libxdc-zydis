call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cmake -B build -T "ClangCL,host=x64" -A x64 & cmake --build build --config Release --target install --clean-first
