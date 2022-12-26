# SmartTLS

SmartTLS is a TLS handshake offloading stack, which leverages programmable NIC (a.k.a SmartNIC). Using SmartTLS, host need not be aware of incoming TLS connection and only deal with established ones, while NIC process whole TCP/TLS handshake including session key exchange. SmartTLS has adventage on short-lived connection where handshake process is used to be bottleneck over most cases. It provides synchronous and device-independent API, so that users can reuse their own conventional application with minimal modification.

For more information, please refer following paper:
https://dl.acm.org/doi/10.1145/3411029.3411034

Also, you can find the evaluation with BlueField-2 SmartNIC here:
https://www.ndsl.kaist.edu/smarttls/

## System Requirements

### Hardware Requirements

SmartTLS needs Mellanox BlueField SmartNIC with ARM processor for offloading. You can find detail of the NIC at:

* [BlueField SmartNIC Ethernet](https://www.mellanox.com/products/BlueField-SmartNIC-Ethernet)

Other processing units but CPU do not need to be equipped in a machine.

### Software requirements

We require the following libraries to build SmartTLS.

* libnuma
* libpthread
* librt
* libgmp
* Linux kernel headers

For Debian/Ubuntu, try apt-get install linux-headers-$(uname -r)
For Fedora/CentOS, try yum install kernel-devel kernel-headers

Also, SmartTLS uses [DPDK](https://www.dpdk.org) for default I/O module. Please refer to [this link](https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html) to figure out the requirements for compiling AccelTCP with DPDK.

You should also ensure that BlueField SmartNIC is properly installed. Please follow [this document](https://docs.mellanox.com/display/BlueFieldSWv25011176/SmartNIC+Operation) to install required drivers and firmwares. We recommend to use screen or minicom to access SmartNIC, and native-compile the program within it. Note SmartNIC driver requires specific OS specs; we tested CentOS 7 on both host and SmartNIC.

Important: You should install public-key accelerator (PKA) which Bluefield software kit provides onto SmartNIC.

### SmartTLS without SmartNIC

SmartTLS can still work with normal NIC that supports DPDK, without NIC offload. In this case, the host network stack will process TLS handshake, and the application remains unmodified, but we do not recommend it due to the performance efficiency.

## Included files

* smartnic/tc_script: Example to guide how to use traffic control (TC) rule on SmartNIC, which redirect or drop a designated flow
* smartnic/bluefield_pka_benchmark: Our benchmark application to evaluate public key cryptography performance of SmartNIC hardware
* smartnic/offload_ssl: DPDK application which offload TCP/TLS handshake
* host/mtcp_ssl_offload: [mTCP](https://github.com/mtcp-stack/mtcp) for user-level network stack. We modified the source code to implement TLS protocol and provide TLS-related API, so Please use our version.
* README.md: this file
* LICENSE: Modified BSD License

We do not include DPDK into our repository, so you also need to prepare it. Please note that host and SmartNIC use different DPDK version. You can find detail in Installation part.

## Installation

First of all, please check if there are any missing things on prerequisites. SmartTLS installation divides into 2 part, host and smartnic.

### Installation on host

1. Prepare DPDK

Download DPDK 18.05 and store at host/mtcp_ssl_offload. Then change the name to dpdk.

```bash
$ wget https://fast.dpdk.org/rel/dpdk-18.05.1.tar.xz
$ tar -xvf dpdk-18.05.1.tar.xz
$ mv dpdk-stable-18.05.1 dpdk
```

We need to enable DPDK poll mode driver to support our SmartNIC
Enter dpdk/config/common_base, and change CONFIG_RTE_LIBRTE_MLX5_PMD to 'y'

2. Setup DPDK

```bash
$ ./setup_linux_env.sh
```

- Press [15] to build target x86_64-native-linuxapp-gcc
- Press [21] or [22] to setup 4096 2MB hugepages
- Press [35] to exit the script

3. Set RTE_SDK and RTE_TARGET environment variables

```bash
$ export RTE_SDK=<downloaded_dpdk_directory>
$ export RTE_TARGET=x86_64-native-linuxapp-gcc
```

4. Setup IP address to interface

Check interface name of SmartNIC port by ifconfig

```bash
$ ifconfig
$ ifconfig <interface_name> x.x.x.x/24 up
```

5. Build mTCP library

```bash
$ ./configure --with-dpdk-lib=$RTE_SDK/$RTE_TARGET --enable-uctx --enable-bluefield
$ make -j && cd apps/tls_server/ && make -j
```

In case ./configure script prints an error, run the following command and run again:

```bash
$ autoreconf -ivf
```

We provide default web server ssl_server, and you might write your own program using SmartTLS API.

### Installation on SmartNIC

1. Enter to the terminal of SmartNIC. If you use rshim driver to communicate with NIC, following command would do this.

```bash
$ ssh root@192.168.100.2
``` 

You might use screen or minicom to directly access the SmartNIC, in a case of there are any wired connection between two.

```bash
$ screen /dev/rshim0/console
``` 

2. Build DPDK application

Please prepare dpdk 19.xx version. We tested 19.05 and 19.08 version. Then run the setup script.

```bash
$ wget https://fast.dpdk.org/rel/dpdk-19.05.tar.xz
$ tar -xvf dpdk-19.05.tar.xz
$ ./<dpdk_directory>/usertools/dpdk-setup.sh
```

- Build target arm64-bluefield-linux-gcc
- Setup 16 512MB huge pages (SmartNIC use 512MB as default)
- Exit the script

3. Set RTE_SDK and RTE_TARGET environment variables

```bash
$ export RTE_SDK=<dpdk_directory>
$ export RTE_TARGET=arm64-bluefield-linux-gcc
```

4. Compile SmartNIC program (DPDK application)

```bash
$ cd offload_ssl
$ make -j
```

## Running default program (TLS web server)

Both host and SmartNIC have their application. SmartNIC's should be run first, and then host application next.

1. Run application at SmartNIC

At smartnic/offload_ssl, 

```bash
$ ./build/ssloff -c <core_mask> -n 4 -- -m <max_conn>
(e.g. ./build/ssloff -c ff -n 4 -b 03:00.1 -- -m 32768)
```

- core_mask should be 2^k.
- max_conn means hard limit of TLS handshakes that SmartNIC can concurrently handle.

You can configure actual threshold to convert opportunistic offload at tcp.c. concurrent connections more than UPPER_BOUND trigger the SmartNIC does not process handshake offload, and lower than LOWER_BOUND make SmartNIC return its state.

2. Run mTCP application at host

At host/mtcp_ssl_offload/apps/tls_server,

```bash
$ ./ssl_server -p <storage_directory> -f epserver.conf -N <core_num>
(e.g. ./ssl_server -p www -f epserver.conf -N 8)
```

- mTCP loads all files at storage_directory to main memory to serve them quickly. Please do not put too heavy files exceeding your RAM capacity.

## Notes

Currently SmartTLS support TLS 1.2, TLS_RSA_WITH_AES_256_CBC_SHA and TLS_RSA_WITH_AES_256_GCM_SHA384. SmartNIC can offload public crypto algorithm with RSA certificate, both 2048 and 4096 bits.

SmartTLS source code is distributed under the Modified BSD License. For more detail, please refer to the LICENSE.
