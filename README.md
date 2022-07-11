# HiveV5 keystream decryptor PoC

## Introduction

The Hive sample analyzed and referred to in this document was randomly chosen from [this list](https://github.com/rivitna/Malware/blob/main/Hive/Hive_samples.txt) created by [@rivitna](https://twitter.com/rivitna2) to which my warmest thanks go. Artifacts are available on the VirusTotal platform.

In this document, file a0h2uih3d2.exe has been taken as a reference

MD5: 15CF5E0DA094ACDD751A513402A8C941  
SHA-1: 72E15AC4473903C814E65E3C06F54EB0399580AA  
SHA-256: 335D2E4A743D059955760ECF2EC25EE86D36AA60B096C9180E860C64EF78EE55

You can download it [here](https://www.virustotal.com/gui/file/335d2e4a743d059955760ecf2ec25ee86d36aa60b096c9180e860c64ef78ee55).

To get an idea of the complexity of ransomware, please take a look at [this analysis](https://www.microsoft.com/security/blog/2022/07/05/hive-ransomware-gets-upgrades-in-rust/) published by Microsoft Threat Intelligence Center (MSTIC).

Please read carefully the entire document before starting playing with code!

## A brief overview on Hive v5

In recent months, I have channeled most of my strength into the study and reverse engineering of the Hive v5 encryption algorithm. I had the pleasure of collaborating with a great malware analyst and reverse engineer [@rivitna](https://twitter.com/rivitna2) who in the past has analyzed previous versions of Hive and published code and PoCs regarding their encryption mechanisms. He has contributed (not a little) to identify the components involved in the encryption operations of Hive v5, which being written in RUST has become more difficult to analyze. I found something in common with Babuk, another very important ransomware whose sources were disclosed in June 2021:

-   key exchange algorithm;
-   list of processes to be closed before starting the 1256 encryption threads.

Hive ransomware v5 running on a victim system generates two cleartext keys, using the algorithm in the below evidence, based on *QueryPerformanceCounter* and on *QueryPerformanceFrequency* Windows APIs.

Please take a look at [this](https://docs.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancecounter) Microsoft page for more information on *QueryPerformanceCounter* APIs, [here](https://docs.microsoft.com/en-us/windows/win32/api/profileapi/nf-profileapi-queryperformancefrequency) for *QueryPerformanceFrequency.*

*QueryPerformanceCounter* is a very accurate time counter. When called, it returns the time elapsed since the last time the PC was turned on.

*QueryPerformanceFrequency* returns the value (frequency) of the performance counter. It has a fixed value of 0x989680. It means that the *QueryPerformanceCounter* value is updated 0x989680 times per second, which is 10,000,000 times.

The two cleartext keys have a size of 0xCFFF00 bytes and are generated one at a time byte by byte. Below is the snippet that allows the creation of 0xA00000 bytes array, which is the largest part of the so called **cleartext key** with which Hive encrypts the files on the victim's PC.

![snippetGenKeyCleartext](https://user-images.githubusercontent.com/72123074/178325017-4de4fc2b-9f3e-4c18-88b8-a6106a4b366c.jpg)

Each byte of the key is obtained by taking the value of the AL register. The EAX register contains the result of the 0044ADE0 function renamed with the label *createByte* which implements the difference between the current time instant and the initial seed value, calculated at the first call of the function 0044A850 renamed with the label *call_to_QueryPerformanceCounter*.

Below is the code written in C++ for generating a cleartext key:

![c++GenKeyCleartext](https://user-images.githubusercontent.com/72123074/178324982-14a66388-dbc6-4411-8d13-c8c630aa2f1d.jpg)

The algorithm is very simple, even if inside the 0044ADE0 function, instructions have been inserted that perform redundant operations and various conditional jumps to try to delay the execution time of the code during the generation of the cleartext key:

![useless-conditions](https://user-images.githubusercontent.com/72123074/178325019-f7010a9f-6fab-4f19-ba7b-2c8cef71b970.jpg)

In the **HiveRansomwareV5_custom_keygen_PoC** folder you’ll find the raw code reversed from the analyzed Hive v5 sample. It is not optimized code like the one found in malware, because I needed not to miss a single line of code from the compiled version.

In the **HiveRansomwareV5_custom_keygen_PoC-optimized** folder you’ll find the optimized code derived from the above mentioned raw code. In this version the code is much easier to read than the raw one, in order to understand the functionality it implements.

**Both versions need to be customized with your user before running them in order to save the generated cleartext key on your Desktop.**

Both cleartext keys are generated using the same algorithm.  
A cleartext key is made of 0xA00000 ~~secure randomly generated~~ bytes. Then the first 0x2FFF00 bytes are copied at the end, creating a final 0xCFFF00 bytes cleartext key.

![memcpy2FFF00](https://user-images.githubusercontent.com/72123074/178325001-52022aa9-a00a-4a7d-9cb4-d6c75a913395.jpg)

Then it uses the two generated key to encrypt files, but first of all Hive ransomware v5 encrypts the generated keys into a custom structure (hereafter called **keystream**) and places them at the root of each drive it encrypts using the .key extension. For example, if you have both drives C and D installed on your system, the encrypted keystreams will be present in the root of each drive.

![keysAtRoot](https://user-images.githubusercontent.com/72123074/178324993-6a0bb054-33a2-4851-b987-3ea7e2dabda5.jpg)

Hive ransomware v5 uses the generated cleartext keys to encrypt files using the XOR instruction, so we are facing a very fast symmetric encryption on modern x86/x64 CPUs.

## How Hive v5 protects itself, how a cleartext becomes a keystream

Hive ransomware v5 needs to protect the cleartext generated key, encrypting it two times, hereafter we will call these **rounds**. It takes two rounds of encryption to get the final keystream.

To accomplish this, the following steps are done at each rounds:

1.  Generation of 32 bytes private key, using the same algorithm to create each byte of the key;
2.  Using the Curve25519 elliptic curve algorithm for Diffie-Hellman key exchange, Hive derives a public key from the just generated private key;
3.  Using Curve25519 again, Hive generates a shared key from the private key just generated and Hive affiliate’s public key (changes in every Hive artifact v5);
4.  Generation of a 24 bytes nonce, like a kind of IV, using the same algorithm for private key and cleartext key;
5.  Using the HChaCha20 algorithm, the key to encrypt the cleartext generated key is derived;
6.  Using the key created in step 5 and the nonce created in step 4, Hive encrypts the cleartext key using XChaCha20 algorithm. This operation produces also a 16 bytes MAC (Message Authentication Code) to ensure the integrity of the encryption process.

Step 3 guarantees the creation of a keystream that can be opened by a double pair of private keys, those generated by Hive during encryption and those that the Hive affiliate generated when he compiled the ransomware for us.

![keystreamCreation](https://user-images.githubusercontent.com/72123074/178324996-0393e927-243b-48df-89e0-7aab314686a4.jpg)

## The idea behind the bruteforce

At the end of this description one particular point is evident: the cleartext key, the private key and the nonce used for both rounds of encryption are generated by the same function above (0044ADE0 aka *createByte*). **The function 0044ADE0 is conditioned by the time that the CPU takes to execute the code called within the for loop.**

Taking a look at the figure above which highlights the keystream structure after the two rounds of encryption, it is evident that we only have free access to the **nonce** (otherwise Hive affiliates would not know how to decrypt the files).

So let's focus on the NONCE, which is 24 bytes long:

NONCE: 40 A4 08 6C D0 D0 34 98 FC 60 C4 28 8C F0 F0 54 B8 1C 80 E4 48 AC AC 10

**The difference between one byte of the nonce and the next (in absolute value) represents the time elapsed between one iteration and the next. We introduce the concept of fingerprint with this definition.**

NONCE FINGERPRINT: 64 9c 64 64 00 9c 64 64 9c 64 9c 64 64 00 9c 64 9c 64 64 9c 64 00 9c

If we analyze the values obtained we find that the execution time of the code is almost identical with slight variations due in particular to the technology used by the processor in use, (for my tests I used a 10th gen i7 processor and a 5th gen i5, on other systems this fingerprint may differ).

This finding is very important if we think that the nonce is generated by the same function that generates the key in cleartext and above all the private key. Since these values mentioned will also follow this principle, i.e. the difference between the single bytes of the nonce is predictable, then the private key and the cleartext key values will also be predictable.

However, the analyzes have shown that generating an array of 0xA00000 characters hoping to get the same original bytes of the Hive computed cleartext key is very difficult: the variations in the CPU and memory loads affect the speed of execution of the code and often the original cleartext key computed by Hive PE is different (even only for a few bytes) from the computed key by us.

We use this nonce fingerprint to compare it to the fingerprint obtained from the generation of a possible dictionary of 0xA00000 bytes long (this number has been empirically fixed, after a series of tests, it has been seen that statistically in this number of bytes there are the two private keys of 32 bytes each, needed in the two rounds of encryption). If the nonce fingerprint is contained in the dictionary fingerprint we found the right dictionary to start bruteforcing both private keys.

It does not end here, because from the dynamic analyzes conducted on the generation of the nonce, of the cleartext key and also of the private key, it has been verified that the first byte has an average distance different from the second byte, compared to all the other bytes which have almost homogeneous values Let's see in detail:

![hivePrivateKeyFingerprint](https://user-images.githubusercontent.com/72123074/178324989-96ec4347-1d0c-4d35-bf22-88fe2472f9f2.jpg)

As you can see the values of the fingerprint following the first undergo minimal variations, i.e. the distance in absolute value between the first and second byte of the private key most of the time it has values outside the values present in the rest of the fingerprint.

Probably this is due to some optimization algorithms present in the CPU that speed up the execution of the code after the first iteration in the for loop.

## A possible solution

The proposed code reads the nonce of each keystream encryption round, determines its fingerprint and generates a list of possible key dictionaries that contain the possible private key.

To solve the problem relating to the first byte of the fingerprint which is always different from the rest of the key, I thought of doing this:

1.  we create a dictionary of possible leading bytes, taking the unique values of the first 0x110 bytes of the generated dictionary;
2.  we create a list of 31 bytes by taking all the possible combinations starting from the second byte of the generated dictionary;
3.  we create combinations of the first bytes and the remaining generated 31 bytes to create the possible 32 byte private key combinations from which to derive the public key by comparing it with the one in our possession present in the keystream.

When the two public keys coincide we would have found the private key with which the second (last) round of encryption was encrypted. By iterating the operations described so far again we will have the private key to decrypt the first round of encrypted keystream and finally extract the original cleartext key.

## Usage

In the **HiveRansomwareV5-keystream_decryptor** folder you’ll find the VS 2017 sln and a [monocypher](https://monocypher.org/) customized library. The program lets you choose which operation to perform.

![programOptions](https://user-images.githubusercontent.com/72123074/178325013-3a83a9a3-8e90-49a2-a45d-42d9dc6ff797.jpg)

Option "1" is the first to be choosen because it allows you to create a dictionary of "tailor-made" bytes for your PC processor, therefore it should be performed on the encrypted machine, because it is much more likely that you will get values equal to those present in its keystream.

![programOption1](https://user-images.githubusercontent.com/72123074/178325003-99811699-b136-4000-8c4b-0e37fbbb1efd.jpg)

Or alternatively, if the first option doesn’t work, generate your own dictionary by running the malware in the debugger (on the same PC already infected) until the end of the cleartext key generation (just outside the for loop) and save the contents of the memory that contains the cleartext key. In this case you can validate your dictionary using option “3”:

![programOption3](https://user-images.githubusercontent.com/72123074/178325011-70eff7b9-1da1-493f-9225-c1258c1cd6b6.jpg)

Once you have the right dictionary for your keystream, option "2" can also be performed on more powerful computers as they would reduce the time needed to brute the combinations of bytes, without affecting in any way the values of the private keys bytes.

![programOption2_1](https://user-images.githubusercontent.com/72123074/178325004-0b886af6-330a-4ad3-9079-902ae3a684fb.jpg)
![programOption2_2](https://user-images.githubusercontent.com/72123074/178325007-6df0e47a-5389-44ed-950f-71c478816434.jpg)
![programOption2_3](https://user-images.githubusercontent.com/72123074/178325010-633293f7-124b-4e98-b2e0-da47a2f50de5.jpg)

To properly perform the functionality present in option 2, the public key must be extracted. Since not all Hive samples are created equal, it is not very easy to create a universal public key extractor. However, one way that is known to work is to set a breakpoint in this portion of the disassembled after the creation of the nonce. In the evidence below, the public key is passed to function 44E3D8 in order to derive the shared key using curve25519. It is the only place where the public key is revealed throughout the execution of the malware.

![wherePublicKeyIsUsed](https://user-images.githubusercontent.com/72123074/178325024-13c66d85-0ab3-47e4-b95c-787996bc758f.jpg)

Please pay attention when you’re dealing with Visual Studio options. Program output like dictionary generated bytes may be altered if you switch from debug to release and vice versa.

If you want to speed up the brute procedure you can edit the *dictionary_dimension* value in the code, but please mind that decreasing the dictionary size may also decrease the chances of finding private keys.

Also if you decide to use a cleartext byte array generated by running Hive and dumping it from memory, remember to set the size of your dump in the *dictionary_dimension* variable.

## References

<https://github.com/rivitna/Malware/blob/main/Hive/Hive_samples.txt>

<https://www.virustotal.com/gui/file/335d2e4a743d059955760ecf2ec25ee86d36aa60b096c9180e860c64ef78ee55>

<https://www.microsoft.com/security/blog/2022/07/05/hive-ransomware-gets-upgrades-in-rust/>

<https://docs.microsoft.com/en-us/windows/win32/sysinfo/acquiring-high-resolution-time-stamps>

<https://monocypher.org/manual/x25519>

<https://monocypher.org/manual/advanced/poly1305>

<https://monocypher.org/manual/advanced/chacha20>

<https://monocypher.org/manual/aead>

