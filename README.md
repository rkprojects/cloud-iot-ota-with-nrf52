# Cloud IoT OTA Updates with nRF52840 and SIM7600E LTE Module

This project is part of the article: [https://ravikiranb.com/articles/cellular-ota-nrf52/](https://ravikiranb.com/articles/cellular-ota-nrf52/).

This example project builds upon the previous [GitHub project](https://github.com/rkprojects/cloud-iot-with-nrf52). Along with publishing SoC temperature updates, it will also process firmware update request over MQTT and downloads encrypted firmware binary file from the given HTTP(S) URL. Bootloader then flashes the binary file.

# Development Board

Any nRF52840 based custom board or Nordic Semiconductor's offical [nRF52840 DK](https://www.nordicsemi.com/Software-and-Tools/Development-Kits/nRF52840-DK) will work. The project uses only the first two BSP LEDs (trivial indication) and two UARTE instances: one for debug output on usb to serial converter and second one for AT modem. For UART, only the Tx,Rx pins are used, no hardware flow control. 

As of now I have tested this project on my simple custom board based on EBYTE E73-2G4M08S1C module + pyOCD + any [CMSIS-DAP Debug Unit](https://github.com/rkprojects/openlink-v1-cmsis-dap) + Ubuntu 16.04 LTS. If you are also going to use EBYTE module then please note that it is locked by default and should be unlocked with either openocd or (nrfjprog + jlink).

# Get Source Code

`$ git clone https://github.com/rkprojects/cloud-iot-ota-with-nrf52.git`  
`$ cd cloud-iot-ota-with-nrf52`

# Configure Project

Project builds with just a single Makefile similar to nRF52 SDK examples with armgcc. SES IDE is not used as it will be restricted to jlink.

Project is comprised of two sub projects: *bootloader* and *app*. Each sub project includes two board options, like:  

* *app/boards/b840_block* - Custom board.  
* *app/boards/pca10056* - Offical DK board.  

You can use either board's Makefile to adapt to your board. You just have to change the board name in the Makefile. Refer to [SDK documentation for custom boards](https://infocenter.nordicsemi.com/topic/com.nordic.infocenter.sdk5.v15.3.0/sdk_for_custom_boards.html).

## Change Makefile

Lets assume Offical DK board from here, open its Makefile: *app/boards/pca10056/blank/armgcc/Makefile*  

### Set nRF5 SDK Root

Set **SDK_ROOT** variable to either absolute or relative path of nRF5 SDK. (Tested with nRF5_SDK_15.3.0_59ac345)

Repeat this step for *bootloader* project too.


### Select Cloud Target

There are four possible combinations:

* CLOUD_TARGET_AWS_GPRS_SSL: AWS IoT → GRPS SSL APIs  
* CLOUD_TARGET_AWS_MBEDTLS_GPRS_TCP: AWS IoT → mbedTLS → GPRS TCP APIs  
* CLOUD_TARGET_GCP_MBEDTLS_GPRS_SSL: GCP IoT → mbedTLS (JWT only) + GRPS SSL APIs  
* CLOUD_TARGET_GCP_MBEDTLS_GPRS_TCP: GCP IoT → mbedTLS → GPRS TCP APIs  

Set **CLOUD_TARGET** variable to one of the above option.

## Configure UARTE Pins

Open header file *app/include/uarte.h*

* Change UART_MODEM_RX/TX_PIN_PSEL as per the free pins available on the board header. 
* Change UART_DEBUG_RX/TX_PIN_PSEL as per the free pins available on the board header. 

## BK-SIM7600E 4G LTE Board Connections

[BK-SIM7600E](http://and-global.com/index.php/product/SIM7600E%20CAT1.html) is a 4G LTE breakout board from AND Technologies. Any SIMCOM SIM7600E module based board would do for this project. This board's UART pins are at 3.3V levels so it can be directly connected to nRF52840. If board has been used in some other projects then do a factory reset to restore manufacturer settings. UART communication settings are 115200 bps baud rate, 8-N-1 data format.

* Connect UART_MODEM_RX_PIN -> BK-SIM7600E.TX
* Connect UART_MODEM_TX_PIN -> BK-SIM7600E.RX
* Connect DK Board's GND -> BK-SIM7600E.GND
* BK-SIM7600E.GND -> supply GND. It has two ground pins.
* BK-SIM7600E.VCC -> supply 5V

Power key feature of the module is not used. It is always kept ON, soft reset is done by the firmware.

**Note on SIM card: SIM Pin feature is not used. If Pin for your SIM card is enabled then disable it first in your phone and then insert in the module, preferably 4G SIM.**

**Note on PDP Context: By default after registration, module automatically gets PDP contexts and enables them. If your network needs a custom PDP then you will have to add it.**


## Debug Output/Console Connections

Get any USB to Serial converter like FTDI or CP210x. UART communication settings are 115200 bps baud rate, 8-N-1 data format. Converter should have 3.3V logic levels, these are usually configurable.

* Connect UART_DEBUG_RX_PIN -> USB-Serial.TX (Debug Rx is not used)
* Connect UART_DEBUG_TX_PIN -> USB-Serial.RX
* Connect DK Board's GND -> USB-Serial.GND

## Integrate SSL Certificates

By default there are no certificates integrated with source code as these are very specific
to your project. 

Certificates and any other arbitrary file types are stored in a simple read only file system as part of the code (const char array):  

* Create root directory to store files for read only file system:  
    `$ cd app`  
    `$ mkdir rofs_root`  
* Copy all the certificates in PEM or CRT/DER format in this or its sub directory. Any number
of files can be added, limited by flash size. File paths in source code begins from '/' character. Example, If a file named *aws-root-ca.pem* is copied to *app/rofs_root/certs* directory, in source code its path will be */certs/aws-root-ca.pem*
* Generate the file system:  
`$ cd app/scripts`  
`$ python3 generate_rofs.py`  


## Configure IoT Settings

Settings of AWS and GCP are configured in *app/include/aws_iot_config.h*. This file is git ignored for security.     
Default *app/include/_aws_iot_config.h* is included in repo. Copy-rename and configure it before compiling.   
If using GCP, use their long term domain host *mqtt.2030.ltsapis.goog* and convert and concatenate primary, backup Root CA certificate into one PEM file.

# Build and Run

This is tricky. Three binaries go into flash: *MBR (once), Bootloader* and *Application*  
Modified MBR is included in the repository which contains the start address of the Bootloader.  
Bootloader needs a valid application in flash and for that it needs to know its hash.  

Application can be with or without softdevice, bootloader is not dependent on softdevice. However the start address  (for now) is assumed to be **0x1000**. Since softdevice itself contains a MBR it needs to be handled correctly, to do that [nrfutil](https://www.nordicsemi.com/Software-and-tools/Development-Tools/nRF-Util) is required to generate DFU package from target application binaries. The generated DFU package should contain either Application or Softdevice + Application.


## Build Sample Application

`$ cd app/boards/pca10056/blank/armgcc`  
`$ make`  

Build will fail if read-only filesystem is not generated or IoT settings are not configured.

`$ make flash`  

Flash programming must be sector wise else other areas will get erased.  
Generate Application DFU package. Go to top level cloned directory.  

`$ cd scripts`  
`$ nrfutil pkg generate --application ../app/boards/pca10056/blank/armgcc/_build/nrf52840_xxaa.hex 
--application-version 0 --hw-version 52 --sd-req 0 ota_app.zip`


## Build Bootloader

Bootloader needs to know about newly flashed application. This step is only required for local deployment i.e. while flashing the application with debugger. 

`$ cd scripts`  
`$ python3 main.py ota_app.zip -b`


`$ cd bootloader/boards/pca10056/blank/armgcc`  
`$ make`  

Flash Bootloader.  
`$ make flash`  

Flash MBR - only once per board.  
`$ make flash_mbr`  

Connect to debug console with any serial port tools like Cutecom or Minicom to view program output.

## Generate OTA Update Files

OTA update needs two files:

* *JSON* message file whose content should be sent as it is from AWS IoT Core MQTT test client or GCP IoT Update Config message. This is a sensitive file, once it is sent over secure MQTT channel and its purpose is over, destroy it.
* Encrypted binary file that you need to host on any cloud storage/cdn and publicly accessible from HTTP or HTTPS URL, no redirects.

The sample application is versioned, it won't accept old firmware version over MQTT. To try out OTA, increment version number in *app/include/version.h*. Follow the *Application* build steps described earlier except flashing. Bootloader build is not required here because this is OTA update not local update.

`$ cd scripts`  

Let's assume new application version number is 5, supply it with -A command line option. Upto two URLs (primary and alternate) can be supplied for OTA update.  
`$ python3 main.py -j -A 5 -u https://storage.googleapis.com/xyz/ota.ebin 
-a http://host.any/ota.ebin ota_app.zip`  

By default generated OTA files are named as: *ota.json* and *ota.ebin*. You could name them differently, for more details on command line options:  
`$ python3 main.py -h`  

Upload the *ota.ebin* file to the above URLs.

## OTA Update with AWS IoT Core

Application subscribes to topic *test/ota_update*. From AWS IoT Console, connect to MQTT bridge with its test client.
Publish *ota.json* file contents to topic *test/ota_update*. 
Watch the OTA update process on UART debug console.

## OTA Update with GCP IoT Core

For GCP, assuming your device name is *my-device*, application subscribes to topic */devices/my-device/config*. 
From GCP IoT Console, for your device click on *Update Config* and send *ota.json* as *text* to the device. 
Watch the OTA update process on UART debug console.


# Known Issues

* nRF52840 UARTE EasyDMA does not have any realtime way of indicating how much data has been transferred for circular mode use case. Currently circular data transfer progress is implemented with interrupts, but it is inefficient. A more efficient implementation with Programmable peripheral interconnect (PPI) + Timer/Counter is pending.
* For Cloud Target **CLOUD_TARGET_GCP_MBEDTLS_GPRS_SSL**, SIM7600E SSL AT Commands fails in TLS handshake stage for ECC keys when server authentication is enabled.
* For any **xxx_GPRS_SSL** cloud targets once a SSL socket is opened or closed, SIM7600E fails to download file over HTTPS connection. Use HTTP URL or **xxx_MBEDTLS_GPRS_TCP** cloud targets for HTTPS URLs.


# License

Copyright 2019 Ravikiran Bukkasagara <contact@ravikiranb.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

