// HiveRansomwareV5_custom_keygen_PoC.cpp 

#include <iostream>
#include <string>
#include <windows.h>
#include <fstream> 


using namespace std;


unsigned long long FUN_0044F78C(unsigned int param_1, unsigned int param_2, unsigned int param_3, unsigned int param_4);
unsigned int createByte(unsigned int param_1, unsigned int param_2);
unsigned int* call_to_QueryPerformanceCounter();
void FUN_0044AB30(unsigned int* param_1, unsigned int *param_2);


LARGE_INTEGER DAT_0045F0D0; //QueryPerformanceFrequency stored value
LARGE_INTEGER DAT_00451018; //contains the EAX and ECX values of the seed value computed by FUN_0044AB40
int dim_key = 0xCFFF00; //it's the cleartext key dimension
unsigned char* cleartext_key = new unsigned char[dim_key](); //the cleartext key will be written here.

string username = "user";
string pathKeyFile = "C:\\Users\\" + username + "\\Desktop\\cleartext-key.bin";

//////////////////////////////////FUN_0044AB30 vars
unsigned int var6_B30;
BOOL var12_B30;
BOOL result_qpf_B30;
unsigned int qpf_lowpart_B30;
unsigned int qpf_highPart_B30;
unsigned int var16_B30;
unsigned int param2_2_B30;
unsigned int var15_B30;
unsigned int var7_B30;
unsigned int var8_B30;
unsigned int var51_B30;
unsigned int var9_B30;
bool var10_B30;
unsigned int var3_B30;
unsigned int var4_B30;
unsigned long long var1_B30;
unsigned int var5_B30;
unsigned int var20_B30;
unsigned int var23_B30;
unsigned int var5_highPart_B30;
unsigned int local_1c_B30;
unsigned int local_error_B30;
unsigned int param1_2_B30;
unsigned int* var0_param_1 = new unsigned int[5];
unsigned int var2_B30;

/////////////////////////////FUN_0044ADE0 vars
unsigned int* var_5_DE0 = new unsigned int[2]();
unsigned int* var_3_DE0 = new unsigned int[5]();
unsigned int* var_6_DE0 = new unsigned int[4]();





int main()
{
	cout << "HIVE ransomware v5 custom keygen function PoC (not very random!)\n";

	//init DAT_00451018 global value where we will save the seed value
	DAT_00451018.QuadPart = 0x00000000c0000000;

	//seed creation - first call
	unsigned int* seed = call_to_QueryPerformanceCounter();

	//seed creation - second call
	seed = call_to_QueryPerformanceCounter();
	//seed[0] = HIGHPART
	//seed[1] = LOWPART

	unsigned char byte;
	unsigned int result;

	//looping 0xA00000 times the FUN_0044ADE0 function
	for (int i = 0; i < 0xA00000; i++)
	{
		//FUN_0044ADE0 accepts the computed seed value splitted into LOWPART and HIGHPART
		result = createByte(seed[1], seed[0]);
		byte = result >> 8 * 0;
		cleartext_key[i] = byte;
	}

	//copying the first 2FFF00 byte and appending to the and of key, so at 0xA00000
	memcpy(cleartext_key + 0xA00000, cleartext_key, 0x2FFF00);

	std::ofstream outfile(pathKeyFile, std::ofstream::binary);
	outfile.write((const char *)cleartext_key, dim_key);
	outfile.close();
	cout << "\nCleartext key wrote to "+ pathKeyFile +"\n";
	cout << "\nDone!\n\n";
}

//FUN_0044A850 returns two integers one saved in EAX, one in ECX
unsigned int* call_to_QueryPerformanceCounter()
{
	unsigned int local_array1_eax;
	unsigned int local_array1_ebx;
	unsigned int local_array1_ecx;
	LARGE_INTEGER qpf_value_850;
	unsigned int  var_error;
	LARGE_INTEGER qpc_values_850;
	BOOL result_qpc_850;
	unsigned int qpc_highPart_850;
	unsigned int qpc_lowPart_850;
	unsigned int qpf_highPart_850;
	unsigned int qpf_lowPart_850;
	unsigned long long div01_850;
	unsigned long long mul01_850;
	unsigned long long mul02_850;
	unsigned int mul_01_850_lp;
	unsigned long long mul03_850;
	unsigned int add01_850;
	unsigned long long div02_850;
	unsigned long long div03_850;
	unsigned int div03_850_hp;
	unsigned int div03_850_lp;
	unsigned int mulSum_850;


	unsigned int* array_param1_850 = new unsigned int[5]();

	//array based on QPC values alternating with zeros 
	unsigned int* array_param2_850 = new unsigned int[4]();
	//result array for FUN_0044A850
	unsigned int* array_output_850 = new unsigned int[3]();

	qpc_values_850.HighPart = 0;
	qpc_values_850.LowPart = 0;

	result_qpc_850 = QueryPerformanceCounter(&qpc_values_850);
	qpc_highPart_850 = qpc_values_850.HighPart;
	qpc_lowPart_850 = (unsigned int)qpc_values_850.QuadPart;
	if (result_qpc_850 == 0)
	{
		var_error = GetLastError();
		cout << "QueryPerformanceCounter error";
	}



	qpf_highPart_850 = DAT_0045F0D0.QuadPart >> 0x20;
	qpf_lowPart_850 = (unsigned int)DAT_0045F0D0.QuadPart;
	if (((unsigned int)DAT_0045F0D0.QuadPart | qpf_highPart_850) == 0)
	{
		DAT_0045F0D0.HighPart = 0;
		DAT_0045F0D0.LowPart = 0;
		result_qpc_850 = QueryPerformanceFrequency(&qpc_values_850);
		if (result_qpc_850 == 0)
		{
			var_error = GetLastError();
			cout << "QueryPerformanceFrequency error!\n";
		}

		DAT_0045F0D0.HighPart = qpc_values_850.HighPart;
		DAT_0045F0D0.LowPart = qpc_values_850.LowPart;

		qpf_lowPart_850 = (unsigned int)qpc_values_850.QuadPart;
		qpf_highPart_850 = qpc_values_850.HighPart;
		if (((unsigned int)qpc_values_850.QuadPart | qpc_values_850.HighPart) == 0)
		{
			std::cout << "attempt to divide by zero /n";

		}
	}

	// retrieving the QPF value stored in DAT_0045F0D0 global variable  
	qpf_value_850 = DAT_0045F0D0;
	div01_850 = FUN_0044F78C(qpc_lowPart_850, qpc_highPart_850, qpf_lowPart_850, qpf_highPart_850);



	mul01_850 = (unsigned long long) div01_850 * qpf_value_850.QuadPart;
	mul_01_850_lp = (unsigned int)mul01_850;
	mul02_850 = (div01_850 & 0xffffffff) * 0x3b9aca00;
	mul03_850 = (unsigned long long)(qpc_lowPart_850 - mul_01_850_lp) * 0x3b9aca00;

	add01_850 = (unsigned int)((unsigned long long)mul03_850 >> 0x20) +
		((qpc_highPart_850 - (unsigned int)((unsigned long long)mul01_850 >> 0x20)) - (unsigned int)(qpc_lowPart_850 < mul_01_850_lp)) * 0x3b9aca00;

	div02_850 = FUN_0044F78C((unsigned int)mul03_850, add01_850, qpf_lowPart_850, qpf_highPart_850);

	mul03_850 = div02_850 + (mul02_850 & 0xffffffff |
		(unsigned long long)(unsigned int)((unsigned int)(div01_850 >> 0x20) * 0x3b9aca00 + (unsigned int)(mul02_850 >> 0x20)) << 0x20);
	qpc_lowPart_850 = (unsigned int)mul03_850;

	div03_850 = FUN_0044F78C(qpc_lowPart_850, (unsigned int)((unsigned long long)mul03_850 >> 0x20), 0x3b9aca00, 0);

	div03_850_hp = (unsigned int)(div03_850 >> 0x20);
	div03_850_lp = (unsigned int)div03_850;
	mulSum_850 = div03_850_lp * 0xc4653600 + qpc_lowPart_850;


	array_param2_850[0] = div03_850_lp;  //qpc.HighPart
	array_param2_850[1] = 0;
	array_param2_850[2] = div02_850;   //qpc.LowPart;
	array_param2_850[3] = 0;


	//array_param1_850 is the output value of FUN_0044AB30
	//array_param2_850 contains QueryPerformanceCounter value splitted by zeroes 
	FUN_0044AB30(array_param1_850, array_param2_850);
	//array_param1_850[0] = 1;
	//array_param1_850[1] = 0;
	//array_param1_850[2] = (EDX) HighPart
	//array_param1_850[3] = 0
	//array_param1_850[4] = (EAX) LowPart

	if ((array_param1_850[0] ^ 1 | array_param1_850[1]) == 0)
	{

		local_array1_eax = array_param1_850[3]; //0
		local_array1_ecx = array_param1_850[2];	//256
		local_array1_ebx = array_param1_850[4]; //85601a0

		//(unsigned int)DAT_00451018.QuadPart ===> DAT_00451018.LowPart;
		qpc_highPart_850 = (unsigned int)DAT_00451018.QuadPart;

		// DAT_00451018.QuadPart >> 0x20  ===> DAT_00451018.HighPart;
		qpc_lowPart_850 = (unsigned int)DAT_00451018.QuadPart >> 0x20;


		//local_30 = ecx
		// local28 = ebx

		qpf_lowPart_850 = (local_array1_ecx - qpc_lowPart_850) - (unsigned int)(local_array1_ebx < qpc_highPart_850);

		//local_array1_eax has 0xc0000000 value only at first iteration, so the if body will be accessed only the first iteration
		if (((local_array1_eax ^ 0xc0000000 | qpc_lowPart_850) != 0) &&
			(0x7fffffff < qpf_lowPart_850 || 0x7fffffff - qpf_lowPart_850 < (unsigned int)(0xfffffffe < local_array1_ebx - qpc_highPart_850)))
		{
			//default execution after first iteration
			//cout << "eax ^ 0xc0000000 | qpc_lowPart) != 0 \n";
		}
		else
		{

			local_array1_ecx = array_param1_850[2];
			local_array1_ebx = array_param1_850[4];
			DAT_00451018.HighPart = local_array1_ecx;
			DAT_00451018.LowPart = local_array1_ebx;

			//cout << "DAT_00451018 value UPDATED !\n";
		}


	}
	else
	{
		std::cout << "called `Option::unwrap()` on a `None` value";
	}


	array_output_850[0] = local_array1_ecx;
	array_output_850[1] = local_array1_ebx;
	array_output_850[2] = 0;

	return array_output_850;

}






//param_2 seedEAX LOWPART
//param_3 seedECX HIGHPART

unsigned int createByte(unsigned int param_1_LP, unsigned int param_3)
{
	//var_5_DE0 in an array, which contains the results of function FUN_0044A850()

	var_5_DE0 = call_to_QueryPerformanceCounter();  //FUN_0044A850 calls  QueryPerformanceCounter
	//var_5_DE0[0]  -> LOWPART
	//var_5_DE0[1]  -> HIGHPART

	//var_3_DE0 is a structure containing SEED values and where updated values return.
	//var_3_DE0  accepts seed values in this way:
	//var_3_DE0 [0] = HighPart SEED ECX
	//var_3_DE0 [1] = 0
	//var_3_DE0 [2] = LowPart SEED EAX
	//var_3_DE0 [3] = 0
	//var_3_DE0 [4] = 0

	var_3_DE0[0] = param_3;
	var_3_DE0[1] = 0;
	var_3_DE0[2] = param_1_LP;
	var_3_DE0[3] = 0;
	var_3_DE0[4] = 0;

	//var_6_DE0 has the same var_5_DE0 values but with arranged values according to FUN_0044AB30
	var_6_DE0[0] = var_5_DE0[0];  //HIGHPART
	var_6_DE0[1] = 0;
	var_6_DE0[2] = var_5_DE0[1];  //LOWPART
	var_6_DE0[3] = 0;


	FUN_0044AB30(var_3_DE0, var_6_DE0);
	//var_3_DE0[0] = 1;
	//var_3_DE0[1] = 0;
	//var_3_DE0[2] = valore1  (ECX)
	//var_3_DE0[3] = 0
	//var_3_DE0[4] = valore2  (EAX)

	if ((var_3_DE0[0] ^ 1 | var_3_DE0[1]) == 0)
	{
		return var_3_DE0[4];  // the output is here
	}

}




//param_1 is the output array

//param_2 :
//param_2[0] is HIGHPART value computed by FUN_0044A850() 
//param_2[1] is LOWPART value computed by FUN_0044A850()  
void FUN_0044AB30(unsigned int* param_1, unsigned int*  param_2)
{

	qpf_highPart_B30 = DAT_0045F0D0.QuadPart >> 0x20;
	qpf_lowpart_B30 = (unsigned int)DAT_0045F0D0.QuadPart;
	if (((unsigned int)DAT_0045F0D0.QuadPart | qpf_highPart_B30) == 0)
	{
		unsigned int uStack60 = 0;
		LARGE_INTEGER local_40;
		result_qpf_B30 = QueryPerformanceFrequency(&local_40);
		if (result_qpf_B30 == 0)
		{
			local_error_B30 = GetLastError();
			unsigned int local_1c = 0;
			std::cout << "QueryPerformanceFrequency error!\n";

		}
		DAT_0045F0D0.QuadPart = 0;
		qpf_lowpart_B30 = (unsigned int)local_40.QuadPart;
		qpf_highPart_B30 = uStack60;
		if ((local_40.QuadPart | uStack60) == 0)
		{
			std::cout << "attempt to divide by zero \n";

		}
	}

	var0_param_1 = param_1;
	var1_B30 = FUN_0044F78C(0x3b9aca00, 0, qpf_lowpart_B30, qpf_highPart_B30);  //  it always returns 64 
	qpf_lowpart_B30 = param_2[1];  
	var5_highPart_B30 = (unsigned int)((unsigned long long) ((unsigned int)var1_B30 >> 9) * 0x44b83 >> 0x20);
	var2_B30 = param_1[0]; //EDX SEED value
	qpf_highPart_B30 = param_1[1]; //param 1[1] is always zero
	var6_B30 = param_2[0]; 
	var3_B30 = (var2_B30 ^ var6_B30 | qpf_highPart_B30 ^ qpf_lowpart_B30) != 0;
	param2_2_B30 = param_2[2];

	if (qpf_highPart_B30 < qpf_lowpart_B30 || qpf_highPart_B30 - qpf_lowpart_B30 < (unsigned int)(var2_B30 < var6_B30))
	{
		var3_B30 = 0xFF;
	}

	param1_2_B30 = param_1[2]; 
	var4_B30 = param1_2_B30 != param2_2_B30;
	if (param1_2_B30 < param2_2_B30)
	{
		var4_B30 = 0xFF;
	}
	if (var3_B30 != 0)
	{
		var4_B30 = var3_B30;
	}
	if (var4_B30 == 1)
	{
		var5_B30 = var2_B30 - var6_B30;
		var7_B30 = (qpf_highPart_B30 - qpf_lowpart_B30) - (unsigned int)(var2_B30 < var6_B30);
		if (qpf_highPart_B30 < qpf_lowpart_B30 || qpf_highPart_B30 - qpf_lowpart_B30 < (unsigned int)(var2_B30 < var6_B30))
		{
			std::cout << "overflow when subtracting durations \n";

		}
		var8_B30 = param1_2_B30; 
		if (param1_2_B30 < param2_2_B30)
		{
			var10_B30 = var5_B30 == 0;
			var5_B30 = var5_B30 - 1;
			var12_B30 = var7_B30 < var10_B30;
			var7_B30 = var7_B30 - var10_B30;
			var20_B30 = var6_B30;
			var23_B30 = qpf_lowpart_B30;
			if (var12_B30)
			{
				std::cout << "overflow when subtracting durations \n";
			}
			var8_B30 = param1_2_B30 + 0x3b9aca00;
		}
		var5_highPart_B30 = var5_highPart_B30 >> 7;
		var9_B30 = (unsigned int)var1_B30 + var5_highPart_B30 * -0x3b9aca00;
		var3_B30 = (var5_B30 ^ var5_highPart_B30 | var7_B30) != 0;
		if (var7_B30 < (var5_B30 < var5_highPart_B30))
		{
			var3_B30 = 0xFF;
		}
		var4_B30 = var8_B30 - param2_2_B30 != var9_B30;
		if (var8_B30 - param2_2_B30 < var9_B30)
		{
			var4_B30 = 0xFF;
		}
		if (var3_B30 != 0)
		{
			var4_B30 = var3_B30;
		}
		if (var4_B30 == 1) goto LAB_0044acc5;
		var51_B30 = 0;
		var7_B30 = 0;
		var15_B30 = 0;
	}
	else
	{
	LAB_0044acc5:
		var16_B30 = 0;
		var51_B30 = var6_B30 - var2_B30;
		var7_B30 = (qpf_lowpart_B30 - qpf_highPart_B30) - (unsigned int)(var6_B30 < var2_B30);
		if (qpf_lowpart_B30 < qpf_highPart_B30 || qpf_lowpart_B30 - qpf_highPart_B30 < (unsigned int)(var6_B30 < var2_B30))
		{
			*var0_param_1 = var16_B30;
			var0_param_1[1] = 0;
		}

		//if the current computed value is less than the Seed value
		if (param2_2_B30 < param1_2_B30)
		{
			var16_B30 = 0;
			var10_B30 = var51_B30 == 0;
			var51_B30 = var51_B30 + -1;
			var12_B30 = var7_B30 < var10_B30;
			var7_B30 = var7_B30 - var10_B30;
			if (var12_B30)
			{
				*var0_param_1 = var16_B30;
				var0_param_1[1] = 0;
			}

			//then add 0x3b9aca00 to the current value
			param2_2_B30 = param2_2_B30 + 0x3b9aca00;
		}
		var15_B30 = param2_2_B30 - param1_2_B30;
	}
	var0_param_1[2] = var51_B30;
	var0_param_1[3] = var7_B30;
	var0_param_1[4] = var15_B30;
	var0_param_1[1] = var7_B30;
	var0_param_1[0] = 1;


}




//param1 = QueryPerformanceCounter LOWPART value
//param2 = QueryPerformanceCounter HIPART value
//param3 = QueryPerformanceFrequency value
//param4 is always 0
unsigned long long FUN_0044F78C(unsigned int param_1, unsigned int param_2, unsigned int param_3, unsigned int param_4)

{
	int var1_78C;
	unsigned char var2_78C;
	unsigned int var3_78C;

	var1_78C = 0x1f;
	if (param_4 != 0)
	{
		for (; param_4 >> var1_78C == 0; var1_78C = var1_78C + -1) {
		}
	}
	if (param_4 != 0)
	{
		//var2_78C = (byte)var1_78C;
		//var3_78C = param_4 << (~var2_78C & 0x1f) | (param_3 >> (var2_78C & 0x1f)) >> 1;
		//if (param_2 < var3_78C) {
		//	var3_78C = ((uint)(CONCAT44(param_2, param_1) / (ulonglong)var3_78C) >> 1) >> (var2_78C & 0x1f);
		//	return (ulonglong)
		//		(var3_78C - ((param_2 - (int)((ulonglong)var3_78C * (ulonglong)param_3 >> 0x20)) -
		//		(uint)(param_1 < (uint)((ulonglong)var3_78C * (ulonglong)param_3)) <
		//			param_4 * var3_78C));
		//}
		//var3_78C = ((uint)(CONCAT44(param_2 - var3_78C, param_1) / (ulonglong)var3_78C) >> 1 | 0x80000000) >>
		//	(var2_78C & 0x1f);
		//return (ulonglong)
		//	(var3_78C - ((param_2 - (int)((ulonglong)var3_78C * (ulonglong)param_3 >> 0x20)) -
		//	(uint)(param_1 < (uint)((ulonglong)var3_78C * (ulonglong)param_3)) <
		//		param_4 * var3_78C));
	}
	return ((unsigned long long)param_2 % (unsigned long long)param_3 << 0x20 | (unsigned long long)param_1) / (unsigned long long)param_3 & 0xffffffff | (unsigned long long)param_2 / (unsigned long long)param_3 << 0x20;
}




