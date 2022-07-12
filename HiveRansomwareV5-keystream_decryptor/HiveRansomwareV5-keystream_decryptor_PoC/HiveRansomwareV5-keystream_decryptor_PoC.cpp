
#include <Windows.h> 
#include <iostream>
#include <stdio.h>
#include <fstream> 
#include <string>
#include <iostream>
#include <sstream>
#include <vector>
#include <iterator>
#include <iomanip>
#include <thread>
#include <set>
#include <string_view>
#include <functional>
#include <algorithm>
#include <string>
#include "monocypher.h"



typedef unsigned char BYTE;


//methods
void dictionary_generation_using_encrypted_keystream();
void check_dictionary_vs_keystream();
boolean brute_privatekey(std::string round, unsigned char* keystream, std::set<unsigned char> insiemeByteIniziali, unsigned char* chiavePubblicaEstratta);
std::set<unsigned char> create_leading_byte_dictionary(unsigned char* keystream);
void bruteforce_existing_keystream_using_computed_dictionary();
unsigned int* createSeed();
unsigned int createbyte(unsigned int* seed);
void openFile(std::string file_name, unsigned char* buffer, int dim);
unsigned char* fingerprint(unsigned char* bytes, unsigned int dim_bytes);

unsigned long long divi;

//nonce used for crypto_hchacha20 for key derivation from curve25519 shared key
BYTE hchacha20_nonce[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };

//basepoint used for deriving public key from computed private key
BYTE basepoint[32] = { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

//declaration of the hive couple of public keys 2x 32 bytes;
//obviously it comes from the HIVE executable that encrypted your files
//
//first 32 bytes are for the 1st round of encryption
//last 32 bytes are for the 2nd round of encryption
//so the first key to be used in decryption of keystream is the last one

//this is the public key extracted from the a0h2uih3d2.exe sample.
//please refer to the readme on how the public key could be extracted
BYTE hivePublic[64] = {
		0x2F, 0xD5, 0xC4, 0x04, 0x5A, 0xD3, 0x88, 0x9E, 0x3D, 0x5A, 0x8E, 0xEE, 0xD0, 0x86, 0x03, 0x06,
		0xD5, 0x01, 0xB9, 0x40, 0x03, 0x77, 0xCF, 0x23, 0xA0, 0x1F, 0xE1, 0xA3, 0x86, 0x8B, 0x03, 0x3F,
		0x77, 0x51, 0x0B, 0xB7, 0x48, 0x17, 0x50, 0xFD, 0xC0, 0xCE, 0xEC, 0xA7, 0x48, 0x57, 0x42, 0xF3,
		0x4D, 0x20, 0xBC, 0x27, 0x0E, 0xD2, 0xB0, 0x3C, 0x58, 0xE4, 0xDB, 0x32, 0x9E, 0x2F, 0x3A, 0x03 };


//dictionary dimension for private key generation
//change it you plan to use a different dictionary in size
int dictionary_dimension = 0xA00000;

//array for storing generated bytes to be used as a dictionary
unsigned char* dictionary = new unsigned char[dictionary_dimension]();

//fixed value, nonce is always 24 bytes long
unsigned int nonce_dimension = 0x18;
//starting byte for computing nonce fingerprint 
unsigned int fingerprint_starting_byte = 1;
//the working path will be updated when selecting files
std::string currentWorkingPath = "";

unsigned int nonce_fingerprint_dim = nonce_dimension - 0x2 - fingerprint_starting_byte; //dim of nonce fingerprint
unsigned int dictionary_fingerprint_dim = dictionary_dimension - 0x2 - fingerprint_starting_byte;//dim of dictionary fingerprint

//array for storing recovered privateKeys during bruteforce
unsigned char* recovered_PK = new unsigned char[32]();

//array for storing nonce byte distances (fingerprint) found in keystream 
unsigned char* nonce_fingerprint_array = new unsigned char[nonce_fingerprint_dim]();

//array for storing dictionary byte distances (fingerprint) 
unsigned char* dictionary_fingerprint_array = new unsigned char[dictionary_fingerprint_dim]();

//used in fingerprint() function, used for storing the distance from one byte and the next
int dist = 0;

//array for storing public key extracted from keystream
unsigned char* publicKey_fromKeystream = new unsigned char[32]();





int main()
{


	std::string j;

	std::cout << "Hive ransomware V5 - keystream decryptor PoC" << std::endl;
	std::cout << "--------------------------------------------\n" << std::endl;
	std::cout << "1. dictionary generation using keystream" << std::endl;
	std::cout << "2. bruteforce existing keystream using computed dictionary" << std::endl;
	std::cout << "3. check your dictionary using keystream" << std::endl;
	std::cout << "your move: " << std::endl;

	j = std::cin.get();

	if (j == "1")
	{
		dictionary_generation_using_encrypted_keystream();
	}
	else
		if (j == "2")
		{
			bruteforce_existing_keystream_using_computed_dictionary();
		}
		else
			if (j == "3")
			{
				check_dictionary_vs_keystream();
			}



}

//option 3
void check_dictionary_vs_keystream()
{
	//open the keystream file
	std::cout << "Please enter the keystream path: \n";
	std::string path_keystream;
	std::cin >> path_keystream;
	path_keystream.erase(remove(path_keystream.begin(), path_keystream.end(), '\"'), path_keystream.end());
	std::ifstream ifs(path_keystream.c_str());

	//updating current working path based on keystream position in file system
	currentWorkingPath = path_keystream.substr(0, path_keystream.find_last_of("/\\"));

	if (!ifs)
	{
		std::cout << "error opening keystream file!";
	}
	else
	{
		unsigned char* nonce = new unsigned char[nonce_dimension]();

		//
		std::cout << "Reading the nonce...\n";
		openFile(path_keystream, nonce, nonce_dimension);


		//fingerprint computation
		nonce_fingerprint_array = fingerprint(nonce, nonce_dimension);

		std::cout << std::hex << "Nonce fingerprint: ";
		for (int k = 0; k < nonce_fingerprint_dim; k++)
		{
			std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)nonce_fingerprint_array[k]) << " ";
		}
		std::cout << "\n";


		std::cout << "Please enter your 0xA00000 bytes dictionary file extracted from memory: \n";
		std::string dictionary_path;

		std::cin >> dictionary_path;
		dictionary_path.erase(remove(dictionary_path.begin(), dictionary_path.end(), '\"'), dictionary_path.end());
		std::ifstream ifs(dictionary_path.c_str());

		if (!ifs)
		{
			std::cout << "error opening file!";
		}
		else
		{
			unsigned char* dictionary = new unsigned char[0xA00000]();
			openFile(dictionary_path, dictionary, 0xA00000);

			//computing memory extracted dictionary fingerprint 
			unsigned char* dictionary_fingerprint_array = new unsigned char[0xA00000 - 0x2]();
			dictionary_fingerprint_array = fingerprint(dictionary, 0xA00000 - 0x2);


			//converting nonce_fingerprint array to vector
			std::vector<unsigned char> nonce_fingerprint_vector(nonce_fingerprint_array, nonce_fingerprint_array + nonce_fingerprint_dim);

			//converting just generated dictionary array to vector
			std::vector<unsigned char> dictionary_fingerprint_vector(dictionary_fingerprint_array, dictionary_fingerprint_array + 0xA00000);

			//searching for same nonce fingerprint in just generated dictionary
			auto it = std::search(
				dictionary_fingerprint_vector.begin(),
				dictionary_fingerprint_vector.end(),
				nonce_fingerprint_vector.begin(),
				nonce_fingerprint_vector.end());


			//saveing both the computed dictionary and its fingerprint to disk
			if (it, it != dictionary_fingerprint_vector.end())
			{
				std::cout << "\nFound same nonce fingerprint in dictionary!\nCongratulations, you can use your dictionary to brute private keys\n";


			}
			else
			{
				std::cout << "\nUnfortunately no nonce fingerprint found in dictionary!\n\n";

			}

		}
	}
}

//option 2
void bruteforce_existing_keystream_using_computed_dictionary()
{
	//create space for storing the encrypted keystream
	unsigned char* keystream = new unsigned char[0xCFFF90]();


	std::cout << "Please enter the keystream path: \n";
	std::string path_keystream;
	std::cin >> path_keystream;
	path_keystream.erase(remove(path_keystream.begin(), path_keystream.end(), '\"'), path_keystream.end());
	std::ifstream ifs(path_keystream.c_str());

	//updating current working path based on keystream position in file system
	currentWorkingPath = path_keystream.substr(0, path_keystream.find_last_of("/\\"));

	if (!ifs)
	{
		std::cout << "error opening keystream file!";
	}
	else
	{
		//read the encrypted keystream
		std::cout << "Reading keystream file...\n";
		openFile(path_keystream, keystream, 0xCFFF90);

		//extract our  pubblic key x25519 (from 0x18 o 0x20 )
		std::cout << "Extracting round 2 public key...\n";
		unsigned char* curve25519_pub_round2 = new unsigned char[0x20]();
		memcpy(curve25519_pub_round2, keystream + 0x18, 0x20);

		std::cout << "Please enter the dictionary file generated: \n";
		std::string dictionary_path;
		//std::getline(std::cin, dictionary_path);

		std::cin >> dictionary_path;
		dictionary_path.erase(remove(dictionary_path.begin(), dictionary_path.end(), '\"'), dictionary_path.end());
		std::ifstream ifs(dictionary_path.c_str());

		if (!ifs)
		{
			std::cout << "error opening file!";
		}
		else
		{
			unsigned char* dictionary = new unsigned char[dictionary_dimension]();
			openFile(dictionary_path, dictionary, dictionary_dimension);

			//to create the dictionary of possible leading bytes, I read the unique values of the dictionary file created earlier
			std::cout << "Creating leading bytes dictionary for private key...\n";
			std::set<unsigned char> leadingBytesArray = create_leading_byte_dictionary(dictionary);

			std::cout << "Creating list of possible private keys...\n";
			//2nd is the round of encryption, starting from the last encryption round
			boolean result = brute_privatekey("2nd", dictionary, leadingBytesArray, curve25519_pub_round2);

			if (result == true)
			{
				//next step
				//use recovered private key stored in recovered_PK to decrypt 2nd round

				//extract  XChaCha20 NONCE(stored from 0x0 to 0x18)
				std::cout << "Extracting XChaCha20 nonce round2...\n";
				unsigned char* xchacha20_nonce_round2 = new unsigned char[0x18]();
				memcpy(xchacha20_nonce_round2, keystream, 0x18);

				//extract  encrypted data(stored from 0x38)
				std::cout << "Extracting encrypted data ...\n";
				unsigned char* enc_data_round1 = new unsigned char[0xCFFF48]();
				memcpy(enc_data_round1, keystream + 0x38, 0xCFFF48);

				//extract mac round2
				unsigned char* mac_round2 = new unsigned char[0x10]();
				//0xCFFF80 sarebbe la dimensione totale CFFF90 meno gli ultimi 16 byte
				//visto che il mac si trova alla fine della struttura cifrata
				memcpy(mac_round2, keystream + 0xCFFF80, 0x10);

				//ectract hive last (round2) public key
				unsigned char* hivePubKey_round2 = new unsigned char[0x20]();
				memcpy(hivePubKey_round2, hivePublic + 0x20, 0x20);

				unsigned char* sharedKey_round2 = new unsigned char[0x20]();

				//deriving shared key from recovered private key and hive round2 public key
				crypto_x25519(sharedKey_round2, recovered_PK, hivePubKey_round2);

				unsigned char* key_round2 = new unsigned char[32]();
				BYTE hchacha20_nonce[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
				//derive key from curve25519 shared key
				crypto_hchacha20(key_round2, sharedKey_round2, hchacha20_nonce);

				unsigned char* dec_data_round1 = new unsigned char[0xCFFF48]();

				if (crypto_unlock(dec_data_round1, key_round2, xchacha20_nonce_round2, mac_round2, enc_data_round1, 0xCFFF48))
				{
					//Message corrupted or wrong key
					std::cout << "stream NOK!\n";
				}
				else
				{
					//Message ok and right key
					std::cout << "stream OK!\n";

					//extract our  pubblic x25519 (stored at 0x18)
					std::cout << "Extracting round 1 public key...\n";
					unsigned char* curve25519_pub_round1 = new unsigned char[0x20]();
					memcpy(curve25519_pub_round1, dec_data_round1 + 0x18, 0x20);

					std::cout << "Creating list of possible private keys...\n";
					//2nd is the round of encryption, starting from the last encryption round
					boolean result = brute_privatekey("1st", dictionary, leadingBytesArray, curve25519_pub_round1);

					if (result == true)
					{
						//last step
						//use recovered private key stored in recovered_PK to decrypt 1st round

						//extract  XChaCha20 NONCE(stored from 0x0 to 0x18)
						std::cout << "Extracting XChaCha20 nonce round1...\n";
						unsigned char* xchacha20_nonce_round1 = new unsigned char[0x18]();
						memcpy(xchacha20_nonce_round1, dec_data_round1, 0x18);

						//extract encrypted cleartext key (stored from 0x38)
						std::cout << "Extracting encrypted cleartext key ...\n";
						unsigned char* enc_cleartext_key = new unsigned char[0xCFFF00]();
						memcpy(enc_cleartext_key, dec_data_round1 + 0x38, 0xCFFF00);

						//extract mac round1 (stored after 
						unsigned char* mac_round1 = new unsigned char[0x10]();
						//0xCFFF38 = 0x18+0x20+0xCFFF00
						memcpy(mac_round1, dec_data_round1 + 0xCFFF38, 0x10);

						//ectract hive first (round1) public key
						unsigned char* hivePubKey_round1 = new unsigned char[0x20]();
						memcpy(hivePubKey_round1, hivePublic, 0x20);

						unsigned char* sharedKey_round1 = new unsigned char[0x20]();

						//deriving shared key from recovered private key and hive round2 public key
						crypto_x25519(sharedKey_round1, recovered_PK, hivePubKey_round1);

						unsigned char* key_round1 = new unsigned char[32]();
						BYTE hchacha20_nonce[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
						//derive key from curve25519 shared key
						crypto_hchacha20(key_round1, sharedKey_round1, hchacha20_nonce);

						unsigned char* dec_cleartext_key = new unsigned char[0xCFFF00]();

						if (crypto_unlock(dec_cleartext_key, key_round1, xchacha20_nonce_round1, mac_round1, enc_cleartext_key, 0xCFFF00))
						{
							//Message corrupted or wrong key
							std::cout << "stream NOK!\n";
						}
						else
						{
							//Message ok and right key
							std::cout << "stream OK!\n";


							std::ofstream fileDEC;
							fileDEC.open(currentWorkingPath + "\\decrypted_keystream.key", std::ios_base::binary);
							fileDEC.write((const char*)dec_cleartext_key, 0xCFFF00);
							fileDEC.close();
							std::cout << "decrypt completed succesfully!\n";
						}

					}



				}


			}



		}


	}


}

//option 1
void dictionary_generation_using_encrypted_keystream()
{
	//open the keystream file
	std::cout << "Please enter the keystream path: \n";
	std::string path_keystream;
	std::cin >> path_keystream;
	path_keystream.erase(remove(path_keystream.begin(), path_keystream.end(), '\"'), path_keystream.end());
	std::ifstream ifs(path_keystream.c_str());

	//updating current working path based on keystream position in file system
	currentWorkingPath = path_keystream.substr(0, path_keystream.find_last_of("/\\"));

	if (!ifs)
	{
		std::cout << "error opening keystream file!";
	}
	else
	{
		unsigned char* nonce = new unsigned char[nonce_dimension]();

		//
		std::cout << "Reading the nonce...\n";
		openFile(path_keystream, nonce, nonce_dimension);


		//fingerprint computation
		nonce_fingerprint_array = fingerprint(nonce, nonce_dimension);

		std::cout << std::hex << "Nonce fingerprint: ";
		for (int k = 0; k < nonce_fingerprint_dim; k++)
		{
			std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)nonce_fingerprint_array[k]) << " ";
		}
		std::cout << "\n";

		//converting nonce_fingerprint array to vector
		std::vector<unsigned char> nonce_fingerprint_vector(nonce_fingerprint_array, nonce_fingerprint_array + nonce_fingerprint_dim);
		std::cout << "Computing dictionaries: \n";

		//this loop tries to create 7 dictionaries, using 7 different CPU loads.
		//This code may take up more than 2GB of RAM at runtime if you change dictionary_test max value
		for (int dictionary_test = 0; dictionary_test < 7; dictionary_test++) //era 35
		{
			std::cout << '\r' << "Dictionary test no: " << std::dec << dictionary_test;


			//generating a seed
			unsigned int* seed = createSeed();
			//seed[0] returns EDX value - HIGHPART
			//seed[1] returns EAX value - LOWPART

			//dictionary generation just like cleartext key generation
			unsigned char byte;
			unsigned int result;
			for (int i = 0; i < dictionary_dimension; i++)
			{

				result = createbyte(seed);
				byte = (result >> 8 * 0);
				dictionary[i] = byte;

				//it delays code execution to simulate different CPU and memory loads, trying to guess what the CPU load was during encryption
				unsigned int* registerDummy = new unsigned int[dictionary_test];
				for (int k = 0; k < dictionary_test; k++)
				{
					registerDummy[k] = dictionary_test & 0xFFFFFFFF;
				}



			}

			//computing just generated dictionary fingerprint
			dictionary_fingerprint_array = fingerprint(dictionary, dictionary_dimension);
			//converting just generated dictionary array to vector
			std::vector<unsigned char> dictionary_fingerprint_vector(dictionary_fingerprint_array, dictionary_fingerprint_array + dictionary_fingerprint_dim);

			//searching for same nonce fingerprint in just generated dictionary
			auto it = std::search(
				dictionary_fingerprint_vector.begin(),
				dictionary_fingerprint_vector.end(),
				nonce_fingerprint_vector.begin(),
				nonce_fingerprint_vector.end());


			//saving both the computed dictionary and its fingerprint to disk
			if (it, it != dictionary_fingerprint_vector.end())
			{
				std::cout << "\nFound same nonce fingerprint in dictionary at iteration no " << std::dec << dictionary_test << std::dec << "\n";
				std::cout << "Writing dictionary to file \n";


				std::ofstream outfile_keystream(currentWorkingPath + "\\dictionary_" + std::to_string(dictionary_test) + ".bin", std::ofstream::binary);
				outfile_keystream.write((const char *)dictionary, dictionary_dimension);
				outfile_keystream.close();

				//uncomment if you want to see dictionary fingerprints
				//std::ofstream outfile_keystream_distances(currentWorkingPath + "\\dictionary_fingerprint_" + std::to_string(dictionary_test) + ".bin", std::ofstream::binary);
				//outfile_keystream_distances.write((const char *)dictionary_fingerprint_array, dictionary_fingerprint_dim);
				//outfile_keystream_distances.close();
			}





		}
	}



}

// starting from an array of bytes returns the fingerprint
// that is the distance between each byte of the array and the next one.
// used to generate the dictionary and thus allows us to generate a good starting point to retrieve the key
// dim_bytes is the size of the input byte array
unsigned char* fingerprint(unsigned char* bytes, unsigned int dim_bytes)
{
	unsigned char* out = new unsigned char[dim_bytes - 2 - fingerprint_starting_byte]();

	dist = 0;
	int j = 0;
	//std::cout << "fingerprint: ";
	for (int k = fingerprint_starting_byte; k < dim_bytes - 1; k++)
	{
		dist = abs(bytes[k] - bytes[k + 1]);
		//std::cout << std::hex << dist << " ";
		out[k - fingerprint_starting_byte] = dist;
	}
	//std::cout << "\n";
	return out;
}







unsigned int createbyte(unsigned int* seed)
{
	//unsigned int seedEDX = seed[0];
	//unsigned int seedAEX = seed[1];

	LARGE_INTEGER qpf;
	QueryPerformanceFrequency(&qpf);

	LARGE_INTEGER qpc;
	QueryPerformanceCounter(&qpc);


	//divi = (unsigned long long) qpc.QuadPart / qpf.QuadPart;
	unsigned long long mod = (unsigned long long) qpc.QuadPart % qpf.QuadPart;

	unsigned long long out = (unsigned long long) 0x3B9ACA00 * mod;
	unsigned long long out2 = (unsigned long long) out / qpf.QuadPart;


	if (out2 < seed[1])
	{
		unsigned long long out3 = (unsigned long long) out2 + 0x3B9ACA00;
	}

	unsigned long long out3 = (unsigned long long) out2 - seed[1];

	//FUN_00455174(1, 2, 3, 4);

	//unsigned long long weight = (unsigned long long) 0x3B9ACA00 * mod + 0x3B9ACA01; //sono dei pesi, servono a rallentare l'esecuzione per renderla simile alla creazione delle chiavi di Hive
	//unsigned long long weight2 = (unsigned long long) 0x3B9ACA020 * mod + 0x3B9ACA70; //
	return out2;
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
	//out[0] returns EDX value - HIGHPART
	//out[1] returns EAX value - LOWPART


	return out;
}

void openFile(std::string file_name, unsigned char* buffer, int dim)
{

	// open the file:
	std::streampos fileSize;
	std::ifstream file(file_name, std::ios::binary);


	// read the data:
	//buffer = new unsigned char[dim]();
	file.read((char*)&buffer[0], dim);


}


//round can be 2nd or 1st string
boolean brute_privatekey(std::string round, unsigned char* dictionary, std::set<unsigned char> startingBytes_array, unsigned char* publickey_from_keystream_array)
{
	boolean result = false;


	//completePrivateKey means 1 starting byte + 31 bytes array
	std::vector<unsigned char> completePrivateKey(32, 0x00);

	//set to save the unique 31 bytes keys extracted from the dictionary
	std::set<std::vector<unsigned char>> set_possible_31bytes_group;


	unsigned char* ourGeneratedPublicKey_array = new unsigned char[32]();
	unsigned char* ourGeneratedPrivateKey = new unsigned char[32]();

	//attempt counter
	unsigned long attempt = 0;

	//extracting 31 bytes at a time starting from the SECOND element of the dictionary
	for (int i = 1; i < dictionary_dimension - 31; i++)
	{

		std::copy(dictionary + i, dictionary + 31 + i, completePrivateKey.begin() + 1);

		set_possible_31bytes_group.insert(completePrivateKey);

		std::cout << '\r' << "Expanding keys:  " << std::dec << (double)i / (dictionary_dimension) * 100 << " % " << std::flush;

	}

	std::cout << "\nHave been loaded  " << std::dec << set_possible_31bytes_group.size() << " groups of 31 bytes!\n";

	std::cout << "Combining the groups of 31 bytes with the dictionary of starting bytes... \n";

	//converting extracted keystream public key to vector
	std::vector<unsigned char> publicKey_keystream(publickey_from_keystream_array, publickey_from_keystream_array + 32);


	//for each of the possible 31 bytes, we associates one of the starting bytes
	for (auto it = set_possible_31bytes_group.begin(); it != set_possible_31bytes_group.end(); it++)
	{

		//Print_Vector(*it);
		//std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)*it) << " ";
		for (unsigned char k : startingBytes_array)
		{
			std::vector<unsigned char> temp = *it;

			temp[0] = k;

			//converting vector to array for type compatibility with the key derivation algorithm
			std::copy(temp.begin(), temp.end(), ourGeneratedPrivateKey);

			//deriving public key
			crypto_x25519(ourGeneratedPublicKey_array, ourGeneratedPrivateKey, basepoint);

			//converting the generated public key to vector
			std::vector<unsigned char> ourGeneratedPublicKey_vector(ourGeneratedPublicKey_array, ourGeneratedPublicKey_array + 32);


			std::cout << '\r' << "Attempt " << std::dec << attempt << " of " << std::dec << (set_possible_31bytes_group.size()*startingBytes_array.size()) << " -> " << (double)attempt / (set_possible_31bytes_group.size()*startingBytes_array.size()) * 100 << "%" << std::flush;

			//if the generated public key is equal to the extracted public key from keystream... BINGO!!!
			if (ourGeneratedPublicKey_vector == publicKey_keystream)
			{
				std::cout << "\n\n\nWe got the " + round + " encryption round private key!!! \n";
				for (char c : temp)
				{
					std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)c) << " ";

				}
				std::cout << "\n";

				//save the encryption round private key just found
				std::ofstream foundPK;
				foundPK.open(currentWorkingPath + "\\privateKey-round" + round + "-found.bin", std::ios_base::binary);
				foundPK.write((const char*)ourGeneratedPrivateKey, 32);
				foundPK.close();
				std::cout << "privateKey round " + round + " just found written to file!\n";

				//copy detected private key
				memcpy(recovered_PK, ourGeneratedPrivateKey, 0x20);


				result = true;


			}


			attempt++;

			if (result == true)
			{
				break;
			}

		}
		if (result == true)
		{
			break;
		}

	}


	return result;
}



// creates a dictionary of unique bytes from the first 0x110 elements of the dictionary
// the idea is that within these 0x110 bytes there is always the first byte of the private key
std::set<unsigned char> create_leading_byte_dictionary(unsigned char* dictionary)
{
	std::cout << "Creating a unique leading byte dictionary ...\n";

	//getting the first 0x110 bytes of generated dictionary
	int array_dim = 0x110;

	unsigned char* temp_array = new  unsigned char[array_dim]();
	memcpy(temp_array, dictionary, array_dim);


	//initialize a set of unsigned chars
	std::set< unsigned char> first_starting_bytes;

	//collecting unique values
	for (int i = 0; i < array_dim; i++)
	{
		first_starting_bytes.insert(temp_array[i]);
	}



	std::cout << "possible leading bytes: " << first_starting_bytes.size() << "\n ";
	int i = 1;
	for (auto it = first_starting_bytes.begin(); it != first_starting_bytes.end(); it++)
	{

		std::cout << std::setfill('0') << std::setw(2) << std::hex << (0xff & (unsigned int)*it) << " ";
	}
	std::cout << '\n';
	std::cout << '\n';

	return first_starting_bytes;


}



