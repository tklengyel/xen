#!/bin/sh
if [ x"$BUILD_ARCH" = x"arm32" ]
then
    sudo apt-get install -y gcc-arm-linux-gnueabihf
    export CC=arm-linux-gnueabi-gcc
    export XEN_TARGET_ARCH=arm32
    export CROSS_COMPILE=arm-linux-gnueabihf-
fi

git remote add mine https://github.com/tklengyel/xen.git > /dev/null 2>&1
git fetch mine > /dev/null 2>&1

COMMITS=$(git log mine/master.. --oneline  --reverse | grep -v "Travis CI" | cut -d " " -f 1)

for COMMIT in $COMMITS
do
    git checkout $COMMIT

    if [ x"$BUILD_XEN" = x"yes" ]
    then
        mv xen/.config_xen xen/.config
        make -j4 dist-xen > /dev/null 2>&1

        if [ $? -eq 0 ]
        then
            echo Build of $BUILD_ARCH Xen at commit $COMMIT - passed
        else
            echo Build of $BUILD_ARCH Xen at commit $COMMIT - failed
            exit 1
        fi
    fi

    if [ x"$BUILD_XEN_WITH_XSM" = x"yes" ]
    then
        mv xen/.config_xen_with_xsm xen/.config
        make -j4 dist-xen > /dev/null 2>&1

        if [ $? -eq 0 ]
        then
            echo Build of $BUILD_ARCH Xen with XSM at commit $COMMIT - passed
        else
            echo Build of $BUILD_ARCH Xen with XSM at commit $COMMIT - failed
            exit 2
        fi
    fi

    if [ x"$BUILD_STUBDOM" = x"yes" ]
    then
        ./configure > /dev/null 2>&1
        make -j4 dist-stubdom > /dev/null 2>&1

        if [ $? -eq 0 ]
        then
            echo Build of $BUILD_ARCH Xen stubdoms at commit $COMMIT - passed
        else
            echo Build of $BUILD_ARCH Xen stubdoms at commit $COMMIT - failed
            exit 2
        fi
    fi

    if [ x"$BUILD_TOOLS" = x"yes" ]
    then

        ./configure > /dev/null 2>&1
        make -j4 dist-tools > /dev/null 2>&1

        if [ $? -eq 0 ]
        then
            echo Build of x86 Xen tools at commit $COMMIT - passed
        else
            echo Build of x86 Xen tools at commit $COMMIT - failed
            exit 3
        fi

        if [ x"$BUILD_ARCH" = x"x86" ]
        then
            cd tools/tests/xen-access > /dev/null 2>&1
            make > /dev/null 2>&1

            if [ $? -eq 0 ]
            then
                echo Build of x86 xen-access at commit $COMMIT - passed
            else
                echo Build of x86 xen-access at commit $COMMIT - failed
                exit 4
            fi

            cd ../../..
        fi
    fi

    git reset --hard > /dev/null 2>&1
    git clean -xdf > /dev/null 2>&1
done
