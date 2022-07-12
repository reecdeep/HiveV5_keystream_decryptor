
#include <iostream>
#include <string>
#include <windows.h>
#include <fstream> 

using namespace std;
typedef unsigned char BYTE;


//globals
BYTE* cleartext_key = new BYTE[0xCFFF00]();
string username = "user"; //edit this value
string pathKeyFile = "C:\\Users\\" + username + "\\Desktop\\cleartext-key-optimized.bin";

BYTE* seed = new BYTE[2]();


unsigned int* createSeed();
unsigned int createbyte(unsigned int* seed);

int main()
{
	cout << "HIVE ransomware v5 custom keygen function PoC (not very random!) - optimized\n";

	//generating seed
	unsigned int* seed = createSeed();
	//seed[0] -> EDX value - HIGHPART
	//seed[1] -> EAX value - LOWPART

	//generating A00000 bytes
	unsigned char byte;
	unsigned int result;
	for (int i = 0; i < 0xA00000; i++)
	{
		result = createbyte(seed);
		byte = result >> 8 * 0;
		cleartext_key[i] = byte;
	}

	//copying the first 0x2FFF00 bytes of the keystream and pasting them at the end, then to 0xA00000
	memcpy(cleartext_key + 0xA00000, cleartext_key, 0x2FFF00);

	ofstream filekey;
	filekey.open(pathKeyFile, ios_base::binary);
	filekey.write((const char*)cleartext_key, 0xCFFF00);
	filekey.close();
	cout << "\nCleartext key wrote to " + pathKeyFile + "\n";
	cout << "\nDone!\n\n";

}








unsigned int createbyte(unsigned int* seed)
{
	LARGE_INTEGER qpf;
	QueryPerformanceFrequency(&qpf);

	LARGE_INTEGER qpc;
	QueryPerformanceCounter(&qpc);


	unsigned long long div = qpc.QuadPart / qpf.QuadPart;
	unsigned long long mod = qpc.QuadPart % qpf.QuadPart;

	unsigned int out = 0x3B9ACA00 * mod / qpf.QuadPart;


	if (out < seed[1])
	{
		out = out + 0x3B9ACA00;
	}

	out = out - seed[1];

	return out;
}

unsigned int* createSeed()
{
	LARGE_INTEGER qpf;
	QueryPerformanceFrequency(&qpf);

	LARGE_INTEGER qpc;
	QueryPerformanceCounter(&qpc);

	unsigned int* out = new unsigned int[2]();
	out[0] = qpc.QuadPart / qpf.QuadPart;


	unsigned long long mod = qpc.QuadPart % qpf.QuadPart;
	out[1] = 0x3B9ACA00 * mod / qpf.QuadPart;
	//out[0] -> EDX value - HIGHPART
	//out[1] -> EAX value - LOWPART

	

	return out;
}


