# ***🧬 UEFI Firmware Analysis***

<p align="center">
	<img src="Images/Logo_UEFI.png" width="50%">
</p>

This project is dedicated to the analysis of UEFI firmware and system security, providing a structured approach to extracting, inspecting, and understanding the firmware components of a machine. UEFI (Unified Extensible Firmware Interface) serves as the modern replacement for legacy BIOS, playing a crucial role in system initialization, hardware configuration, and Secure Boot enforcement.

By exploring key firmware elements such as the BIOS, EFI System Partition (ESP), UEFI images, and Secure Boot keys, this guide aims to help researchers, security analysts, and developers gain deeper insights into firmware security mechanisms, vulnerabilities, and integrity verification techniques.

The methodology outlined in this project covers the setup of a live analysis environment, extraction of firmware data, and security assessments using industry-standard tools. Whether you're performing a forensic investigation, hunting for vulnerabilities, or validating firmware integrity, this guide serves as a practical resource for navigating UEFI firmware internals.


---
---
---


## ***📑 Table of Contents***
- [Create a live Linux Image](#createalivelinuximagefedora)
- [Boot from USB](#bootfromusb)
- [Install Tools](#installtools)
- [EFI System Partition (ESP)](#efisystempartition)
- [System Firmware (BIOS/UEFI)](#systemfirmwarebiosuefi)
- [Verify UEFI Images](#verifyuefiimages)
- [UEFI Attack Surface](#uefiattacksurface)
- [Hunting for UEFI Firmware Vulnerabilities](#huntingforuefifirmwarevulnerabilities)
- [USB Directory Structure](#usbdirectorystructure)


---
---
---


<div id='createalivelinuximagefedora'/>

## ***🚀 Create a Live Linux Image***

* Download "Fedora LXDE 64bit"
	- [Fedora-LXDE-Live-x86_64-VERSION.iso](https://fedoraproject.org/spins/lxde/)
* Download "Fedora Media Writer"
	- [FedoraMediaWriter-win64-VERSION.exe](https://github.com/FedoraQt/MediaWriter/)
* Create a Bootable USB
	* Run "FedoraMediaWriter-win64-VERSION.exe".
	* Accept the terms and follow the installation process.
	* Launch Fedora Media Writer after installation.
	* Click on "Select .iso file".
	* Select "Fedora-LXDE-Live-x86_64-VERSION.iso".
	* Choose the USB drive where you want to write the image.
	* Click "Write" and wait for the process to complete.
	* Click "Finish".

*Note: If you encounter any issues creating the bootable USB, try using  [Rufus](https://rufus.ie/) or [Balena Etcher](https://etcher.balena.io/) as alternative tools.*


---
---
---


<div id='bootfromusb'/>

## ***💾 Boot from USB***

* Enter BIOS/UEFI pressing F2 or F12 during startup.
* Ensure that the Boot Mode is set to "UEFI Only" or "Both".
* Select to boot from DVD or USB.
* Save settings and reboot.
* Select the option "Test this media 8 start Fedora-LXDE-Live VERSION".
* Open System Tools -> LXTerminal.



---
---
---


<div id='installtools'/>

## ***📦 Install Tools***

* Install [Dmidecode](https://www.nongnu.org/dmidecode/)
	* Package
		```
		sudo dnf install -y dmidecode
		```
	* Help
		```
		dmidecode --help
		```
* Install [UEFI secure boot verification tool]()
	* Table
		```
		| Operating System | Install UEFI secure boot verification tool             |
		|------------------|--------------------------------------------------------|
		| Windows WSL2     | sudo apt-get update && sudo apt-get install sbsigntool |
		| Debian           | sudo apt-get install sbsigntool                        |
		| Ubuntu           | sudo apt-get install sbsigntool                        |
		| Arch Linux       | sudo pacman -S sbsigntools                             |
		| Kali Linux       | sudo apt-get install sbsigntool                        |
		| Fedora           | sudo dnf install sbsigntools                           |
		| Raspbian         | sudo apt-get install sbsigntool                        |
		| Dockerfile       | dockerfile.run/sbverify                                |
		```
	* Package
		```
		sudo dnf install -y sbsigntools
		```
* Install [CHIPSEC](https://chipsec.github.io/) ([Usage](https://chipsec.github.io/usage/Running-Chipsec.html), [Manual](https://github.com/chipsec/chipsec/blob/main/chipsec-manual.pdf)) to analyze the security of PC platforms
	* Dependencies
		```
		sudo dnf install -y kernel kernel-devel-$(uname -r) python3 python3-devel gcc nasm redhat-rpm-config elfutils-libelf-devel git
		```
	* Clone
		```
		git clone https://github.com/chipsec/chipsec
		cd chipsec
		```
	* Requirements
		```
		pip install -r linux_requirements.txt
		```
	* Build
		```
		python setup.py build_ext -i
		```
	* Aliases
		```
		sudo ln -s $(pwd)/chipsec_main.py /usr/local/bin/chipsec_main
		sudo ln -s $(pwd)/chipsec_util.py /usr/local/bin/chipsec_util
		```
	* Help
		```
		chipsec_main --help
		chipsec_util --help

		cd
		```
* Install [UEFI Firmware Parser](https://github.com/theopolis/uefi-firmware-parser)
	* Package
		```
		sudo pip install uefi_firmware
		```
	* Help
		```
		uefi-firmware-parser --help
		```
* Install [Binwalk](https://github.com/ReFirmLabs/binwalk)
	* Package
		```
		sudo dnf install binwalk
		```
	* Help
		```
		binwalk --help
		```
* Install [FwHunt Community Scanner]( https://github.com/binarly-io/fwhunt-scan) and [FwHunt Rules](https://github.com/binarly-io/FwHunt)
	* Dependencies
		```
		sudo dnf install -y rizin
		```
	* Clone
		```
		git clone https://github.com/binarly-io/fwhunt-scan
		cd fwhunt-scan
		```
	* Build
		```
		python setup.py install
		```
	* Requirements
		```
		pip install -r requirements.txt
		```
	* Rules
		```
		git clone https://github.com/binarly-io/FwHunt
		```
	* Help
		```
		fwhunt_scan_analyzer.py --help

		cd
		```


---
---
---


<div id='efisystempartition'/>

## ***📂 EFI System Partition (ESP)***

* List block devices
	```
	lsblk -o NAME,FSTYPE,SIZE,MOUNTPOINT,LABEL
	```
	```
	Note: The ESP typically has a FAT (vfat) filesystem and is relatively small in size, like 100M.
	```
* Mount ESP
	```
	sudo mkdir -p /mnt/esp
	sudo mount /dev/nvme0n1p1 /mnt/esp
	tree /mnt/esp
	```
* Insert another USB
	```
	df -h
	cd /run/media/liveuser/New\ Volume
	```
* BIOS Information
	```
	sudo dmidecode --type bios > BIOS.txt
	cat BIOS.txt
	```
* Folders
	```
	mkdir 00_LinuxLiveBootloaders
	mkdir 01_EfiSystemPartition
	```
* Copy Linux Live Bootloader Files
	```
	sudo cp -r /boot/efi/EFI/ 00_LinuxLiveBootloaders/
	tree 00_LinuxLiveBootloaders/
	```
* Copy ESP data
	```
	cp -r /mnt/esp/EFI/ 01_EfiSystemPartition/
	tree 01_EfiSystemPartition/
	```


---
---
---


<div id='systemfirmwarebiosuefi'/>

## ***🛡 System Firmware (BIOS/UEFI)***

* Firmware Acquisition
	```
	mkdir 02_FirmwareAcquisition && cd 02_FirmwareAcquisition
	```
	```
	sudo chipsec_util spi dump firmware.bin
	```
	```
	cp firmware.bin firmware.backup.bin
	```
	```
	cd ..
	```
* EFI Executables
	```
	mkdir 03_EfiExecutables && cd 03_EfiExecutables
	```
	```
	sudo chipsec_main --module tools.uefi.scan_image -a generate,03_EfiExecutables/efilist.json,../02_FirmwareAcquisition/firmware.bin
	```
	```
	cd ..
	```
* EFI Configuration
	```
	mkdir 04_EfiConfiguration && cd 04_EfiConfiguration
	```
	```
	sudo chipsec_util uefi var-list
	```
	```
	cd ..
	```
* Secure Boot keys
	```
	mkdir 05_SecureBootKeys && cd 05_SecureBootKeys
	```
	```
	sudo chipsec_util uefi var-find PK
	sudo chipsec_util uefi var-find db
	sudo chipsec_util uefi var-find dbx
	sudo chipsec_util uefi var-find KEK
	sudo chipsec_util uefi keys PK_*.bin
	sudo chipsec_util uefi keys db_*.bin
	sudo chipsec_util uefi keys dbx_*.bin
	sudo chipsec_util uefi keys KEK_*.bin
	```
	```
	cd ..
	```
* Files, Sections and Volumes
	```
	mkdir 06_FilesSectionsVolumes && cd 06_FilesSectionsVolumes
	```
	```
	uefi-firmware-parser --extract ../02_FirmwareAcquisition/firmware.bin
	fwhunt_scan_analyzer.py extract ../02_FirmwareAcquisition/firmware.bin modules/
	binwalk --extract --matryoshka ../02_FirmwareAcquisition/firmware.bin
	```
	```
	cd ..
	```


---
---
---


<div id='verifyuefiimages'/>

## ***🔍 Verify UEFI Images***

* Verify bootx64.efi:
	```
	cd /mnt/esp/EFI/Boot
	sbverify --list bootx64.efi
	```
	```
	signature 1
	image signature issuers:
		- /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Production PCA 2011
	image signature certificates:
		- subject: /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows
		issuer:  /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Production PCA 2011
		- subject: /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Windows Production PCA 2011
		issuer:  /C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/CN=Microsoft Root Certificate Authority 2010
	```
* Folders
	```
	mkdir xx_VerifySignedUefiBinaries && cd xx_VerifySignedUefiBinaries
	```
* Verify EFI files:
	```
	nano verify_efi_files.sh
	```
	```
	#!/bin/bash

	EFI_DIR="/mnt/esp/EFI"
	SUMMARY_FILE="verify_efi_files_summary.txt"

	# Initialize counters
	signed_count=0
	unsigned_count=0
	microsoft_signed_count=0
	other_signed_count=0

	# Colors
	RED='\033[0;31m'
	YELLOW='\033[1;33m'
	GREEN='\033[0;32m'
	NC='\033[0m' # No Color

	# Initialize summary file
	echo "" > $SUMMARY_FILE
	echo "UEFI File Verification Summary" >> $SUMMARY_FILE
	echo "------------------------------" >> $SUMMARY_FILE

	# Function to check if the file is signed by Microsoft
	is_microsoft_signed() {
		issuer="$1"
		if [[ "$issuer" == *"Microsoft Corporation"* ]]; then
			return 0
		else
			return 1
		fi
	}

	# Verify each EFI file and log the results
	for file in $(find "$EFI_DIR" -type f -name "*.efi"); do
		echo "----------------------------------------"
		echo "Verifying $file"
		output=$(sudo sbverify --list "$file" 2>&1)
		echo "$output"
		
		if echo "$output" | grep -q "No signature table present"; then
			printf "${RED}%-70s: Possibly Malicious${NC}\n" "$file"
			printf "%-70s: Possibly Malicious\n" "$file" >> $SUMMARY_FILE
			((unsigned_count++))
		elif echo "$output" | grep -q "image signature issuers:"; then
			if is_microsoft_signed "$(echo "$output" | grep "image signature issuers:" -A 1)"; then
				printf "${GREEN}%-70s: Signed by Microsoft${NC}\n" "$file"
				printf "%-70s: Signed by Microsoft\n" "$file" >> $SUMMARY_FILE
				((microsoft_signed_count++))
			else
				printf "${YELLOW}%-70s: Suspicious (Signed by other entity)${NC}\n" "$file"
				printf "%-70s: Suspicious (Signed by other entity)\n" "$file" >> $SUMMARY_FILE
				((other_signed_count++))
			fi
			((signed_count++))
		else
			printf "%-70s: Verification failed or unknown signature format\n" "$file" >> $SUMMARY_FILE
		fi
		echo "----------------------------------------"
	done

	# Print summary
	echo "------------------------------" >> $SUMMARY_FILE
	echo "Total EFI files verified: $((signed_count + unsigned_count))" >> $SUMMARY_FILE
	echo "Signed files: $signed_count" >> $SUMMARY_FILE
	echo "Unsigned files: $unsigned_count" >> $SUMMARY_FILE
	echo "Microsoft signed files: $microsoft_signed_count" >> $SUMMARY_FILE
	echo "Other signed files: $other_signed_count" >> $SUMMARY_FILE

	# Display summary
	cat $SUMMARY_FILE
	```
	```
	chmod +x verify_efi_files.sh
	./verify_efi_files.sh
	cat verify_efi_files_summary.txt
	cd
	```


---
---
---


<div id='uefiattacksurface'/>

## ***🩻 UEFI Attack Surface***

* Folder
	```
	mkdir xx_UefiAttackSurface && cd xx_UefiAttackSurface
	```
* Basic
	```
	sudo chipsec_main > output_chipsec_main.txt
	sudo chipsec_main --json output_chipsec_main.json
	sudo chipsec_main --markdown output_chipsec_main.md
	```
	```
	Visit https://chipsec.github.io/development/Vulnerabilities-and-CHIPSEC-Modules.html to find a list of available CHIPSEC modules
	```
	* CHIPSEC test modules return standard values that can be interpreted as follows:
		* <details>
			<summary>Click to Show/Hide Result Meanings</summary>

			| Result         | Meaning                                                                                                        |
			|----------------|--------------------------------------------------------------------------------------------------------------------|
			| PASSED         | A mitigation to a known vulnerability has been detected                                                            |
			| FAILED         | A known vulnerability has been detected                                                                            |
			| WARNING        | We have detected something that could be a vulnerability but manual analysis is required to confirm (inconclusive) |
			| NOT_APPLICABLE | The issue checked by this module is not applicable to this platform. This result can be ignored                    |
			| INFORMATION    | This module does not check for a vulnerability. It just prints information about the system                        |
			| ERROR          | Something went wrong in the execution of CHIPSEC                                                                   |

		</details>
	* Known vulnerabilities can be mapped to CHIPSEC modules as follows:
		* <details>
			<summary>Click to Show/Hide UEFI Attack Surface Table</summary>

			| Attack Surface / Vector | Vulnerability Description | CHIPSEC Module |
			|------------------------|--------------------------|---------------|
			| Firmware protections in ROM |  |  |
			|  | SMI event configuration is not locked | common.bios_smi |
			|  | SPI flash descriptor is not protected | common.spi_desc |
			|  | SPI controller security override is enabled | common.spi_fdopss |
			|  | SPI flash controller is not locked | common.spi_lock |
			|  | Device-specific SPI flash protection is not used | chipsec_util spi write (manual analysis) |
			|  | SMM BIOS write protection is not correctly used | common.bios_wp |
			|  | Flash protected ranges do not protect BIOS region | common.bios_wp |
			|  | BIOS interface is not locked | common.bios_ts |  |
			|  | SMI configuration is not locked (SMI race condition) | common.smi_lock |
			| Runtime protection of SMRAM |  |  |
			|  | Compatibility SMRAM is not locked | common.smm |
			|  | SMM cache attack | common.smrr |
			|  | Memory remapping vulnerability in SMM protection | remap |
			|  | DMA protections of SMRAM are not in use | smm_dma |
			|  | Graphics aperture redirection of SMRAM | chipsec_util memconfig remap |
			|  | Memory sinkhole vulnerability | tools.cpu.sinkhole |
			| Secure boot |  |  |
			|  | Incorrect protection of secure boot configuration |  |
			|  | Root certificate | common.bios_wp, common.secureboot.variables |
			|  | Key exchange keys and whitelist/blacklist | common.secureboot.variables |
			|  | Controls in setup variable (CSM enable/disable, image verification policies, secure boot enable/disable, clear/restore keys) | chipsec_util uefi var-find Setup |
			|  | TE header confusion | tools.secureboot.te |
			|  | UEFI NVRAM is not write protected | common.bios_wp |
			|  | Insecure handling of secure boot disable | chipsec_util uefi var-list |
			| Persistent firmware configuration |  |  |
			|  | Secure boot configuration is stored in unprotected variable | common.secureboot.variables, chipsec_util uefi var-list |
			|  | Variable permissions are not set according to specification | common.uefi.access_uefispec |
			|  | Sensitive data (like passwords) are stored in UEFI variables | chipsec_util uefi var-list (manual analysis) |
			|  | Firmware doesn't sanitize pointers/addresses stored in variables | chipsec_util uefi var-list (manual analysis) |
			|  | Firmware hangs on invalid variable content | chipsec_util uefi var-write, chipsec_util uefi var-delete (manual analysis) |
			|  | Hardware configuration stored in unprotected variables | chipsec_util uefi var-list (manual analysis) |
			|  | Re-creating variables with less restrictive permissions | chipsec_util uefi var-write (manual analysis) |
			|  | Variable NVRAM overflow | chipsec_util uefi var-write (manual analysis) |
			|  | Critical configuration is stored in unprotected CMOS | chipsec_util cmos, common.rtclock |
			| Platform hardware configuration |  |  |
			|  | Boot block top-swap mode is not locked | common.bios_ts |
			|  | Architectural features not locked | common.ia32cfg |
			|  | Memory map is not locked | memconfig |
			|  | IOMMU usage | chipsec_util iommu |
			|  | Memory remapping is not locked | remap |
			| Runtime firmware (e.g., SMI handlers) |  |  |
			|  | SMI handlers use pointers/addresses from OS without validation | tools.smm.smm_ptr |
			|  | Legacy SMI handlers call legacy BIOS outside SMRAM |  |
			|  | INT15 in legacy SMI handlers |  |
			|  | UEFI SMI handlers call UEFI services outside SMRAM |  |
			|  | Malicious CommBuffer pointer and contents |  |
			|  | Race condition during SMI handler |  |
			|  | Authenticated variables SMI handler is not implemented | chipsec_util uefi var-write |
			|  | SmmRuntime vulnerability | tools.uefi.blacklist |
			| Boot time firmware |  |  |
			|  | Software vulnerabilities when parsing, decompressing, and loading data from ROM |  |
			|  | Software vulnerabilities in implementation of digital signature verification |  |
			|  | Pointers stored in UEFI variables and used during boot | chipsec_util uefi var-write |
			|  | Loading unsigned PCI option ROMs | chipsec_util pci xrom |
			|  | Boot hangs due to error condition (e.g., ASSERT) |  |
			| Power state transitions (e.g., resume from sleep) |  |  |
			|  | Insufficient protection of S3 boot script table | common.uefi.s3bootscript, tools.uefi.s3script_modify |
			|  | Dispatch opcodes in S3 boot script call functions in unprotected memory | common.uefi.s3bootscript, tools.uefi.s3script_modify |
			|  | S3 boot script interpreter stored in unprotected memory |  |
			|  | Pointer to S3 boot script table in unprotected UEFI variable | common.uefi.s3bootscript, tools.uefi.s3script_modify |
			|  | Critical setting not recorded in S3 boot script table | chipsec_util uefi s3bootscript (manual analysis) |
			|  | OS waking vector in ACPI tables can be modified | chipsec_util acpi dump (manual analysis) |
			|  | Using pointers on S3 resume stored in unprotected UEFI variables | chipsec_util uefi var-write |
			| Firmware update |  |  |
			|  | Software vulnerabilities when parsing firmware updates |  |
			|  | Unauthenticated firmware updates |  |
			|  | Runtime firmware update that can be interrupted |  |
			|  | Signature not checked on capsule update executable |  |
			| Network interfaces |  |  |
			|  | Software vulnerabilities when handling messages over network interfaces |  |
			|  | Booting unauthenticated firmware over unprotected network interfaces |  |
			| Misc |  |  |
			|  | BIOS keyboard buffer is not cleared during boot | common.bios_kbrd_buffer |
			|  | DMA attack from devices during firmware execution |  |
		</details>
* SPI Info
	```
	sudo chipsec_util spi info
	sudo chipsec_util spi info > output_spi_info.txt
	```

---
---
---


<div id='huntingforuefifirmwarevulnerabilities'/>

## ***🩻 Hunting for UEFI Firmware Vulnerabilities***

* Folder
	```
	mkdir xx_FirmwareVulnerabilities && cd xx_FirmwareVulnerabilities
	```
* Find Vulnerabilities, Generate SBOMs & CBOMs
	```
	Visit https://risk.binarly.io/
	Upload firmware to https://risk.binarly.io/scan
	```
* Scan Firmware
	```
	fwhunt_scan_analyzer.py scan-firmware --rules_dir $HOME/fwhunt-scan/FwHunt/rules/Vulnerabilities/Lenovo/ ../02_FirmwareAcquisition/firmware.bin
	```


---
---
---


<div id='usbdirectorystructure'/>

## ***🖴 USB Directory Structure***

```
├───New Volume
	|
	├───00_LinuxLiveBootloaders
	├───01_EfiSystemPartition
	├───02_FirmwareAcquisition
	├───03_EfiExecutables
	├───04_EfiConfiguration
	├───05_SecureBootKeys
	├───06_FilesSectionsVolumes
	|
	├───xx_VerifySignedUefiBinaries
	├───xx_UefiAttackSurface
	└───xx_FirmwareVulnerabilities
```
