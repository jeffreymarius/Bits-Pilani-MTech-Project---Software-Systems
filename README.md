# Bits-Pilani-MTech-Project---Software-Systems
This is my MTech Project - "Design, Implementation &amp; Analysis of a m-TLS Authenticated OMCI Channel in Virtualized PON Architectures"

The project contains 3 main modules - voltmf, vomciFuncion, vomciProxy

To build voltmf, vomciFunction, vomciProxy , navigate to the directory and give " go build "

To run voltmf with TLS1.3 - ./voltmf -tls1.3 (If no TLS required please leave out option)

To run vomcFunction with TLS1.3 - ./vomciFunction -tls (If no TLS required please leave out option)
 
To run vomciProxy with TLS1.3 - ./vomciProxy -tls (If no TLS required please leave out option)


Current repo has voltmf<--> vomciFunction with TLS PSK enabled, however vomciFuncion <---> vomcProxy has TLS with AES enabled (the usual TLS)


The PSK is seeded from the AI model - You can refer the pynb files in pynb/ folder which generates the key. (make sure to change the path in the file to your file directory where the repo is present so that the key can be placed in the correct folder for voltmf, vomciFunction to pick it up)

Recent activity:
 - the go_vpd/ folder is a test program which takes vpd algoritm mentioned in the pynb file into go code. It works however, the TLS PSK in voltmf, vomciFunction makes use of OpenSSL C library. So, openssl_vpd/ was developed to create a separate library for VPD algorithm.
 - opnessl_vpd/ has been successfully compiled to generate the libvpd.so and now the work remains in integrating with the TLS PSK OpenSSL library . For this please refer the following file : psk/psk.go. This file currently uses the PSK from the AI model and uses AES encryption, we need to alter that to VPD and make OpenSSL pick up libvpd.so for encryption.

To compile libvpd.so : gcc -fPIC -shared     vpd_cipher.c vpd_core.c     -o libvpd.so     -lcrypto

To verify if libvpd.so is working : 
 export OPENSSL_MODULES=/home/xxxx/openssl_vpd
 openssl enc -d -VPD -provider vpd -provider-path /home/xxxx/openssl_vpd -K 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff -in  enc.bin -out dec.txt

For more design understanding check - 2023MT13044.pptx

For installing BBF modules for packet capture - https://obbaa.broadband-forum.org/installing/#installing. Follow this page steps to install BBF modules to collect packet captures for data learning for AI model.
