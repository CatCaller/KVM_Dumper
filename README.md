# KVM_Dumper

Dumps a process from a Windows KVM guest and rebuilds its PE image. Needs `KVMLib` and `KVM-Folders` next to this folder.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo ./build/dump RainbowSix.exe
```

Use `--pid 1234` instead of a process name. `pe_probe` inspects the rebuilt image.
