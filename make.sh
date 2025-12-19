#!/bin/bash

dir="$(pwd)/build"

if [ -d "$dir" ]; then
    echo "build directory exists, assuming already configured."
    cd $dir
else
    echo "build directory DOES NOT exist, configuring."
    mkdir $dir
    cd $dir
    ../configure --disable-werror
fi

make -j$(nproc) qemu-system-x86_64

if [ $? -eq 0 ]; then
    echo -e "build good, linking...\n------------"
else
    echo "build failed, exiting!"
    exit 1
fi


# Create symlink
echo "sudo needed for symlink..."
sudo ln -sf $dir/qemu-system-x86_64 /usr/bin/qemu

if [ $? -eq 0 ]; then
    echo "Symlink set!"
else
    echo "Symlink failed!"
    exit 1
fi
