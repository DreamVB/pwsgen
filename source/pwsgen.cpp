/*
* @File pwsgen.cpp
* @Info Random Password Generator C++ version
* @Version 1.4
* @By Ben a.k.a DreamVB
*/

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <vector>
#include <random>
#include <ctime>
#include <string>
#include <algorithm>
#include <iomanip>

//Password mask types.
const char *pLowercase = "abcdefghijklmnopqrstuvwxyz";
const char *pUppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char *pDigits = "0123456789";
const char *pSymbol = "!\"#$%&'()*+,-./:;<=>?@[]^_{|}~";
//Const lengths
const int MIN_PWS_LENGTH = 6;
const int MAX_PWS_LEN = 256;
const int MIN_PASSWORDS = 1;
const int MAX_PASSWORDS = 4000;
//Password mask options
bool sUpper;
bool sLower;
bool sDigits;
bool sSymbols;
bool IncludeLineNo;
bool RemoveVowels;

std::string pass_mask;
//Password length and count
int pws_len;
int pws_count;

using namespace std;

std::string Remove_Vowels(const std::string s);
void _showhelp(void);
void _error(std::ostream &obj, int code);
bool is_vowel(const unsigned char c);
void StrUpper(std::string &src);
std::string _getpassword(std::string mask, int length);

std::string Remove_Vowels(const std::string s){
	std::string tmp;
	int x = 0;

	while (x < s.length()){
		if (!is_vowel(s[x])){
			tmp.push_back(s[x]);
		}
		x++;
	}
	return tmp;
}

void _showhelp(std::ostream &obj){
	obj << "DreamVB's Password Generator v1.4" << std::endl <<
		"Simple Usage pwsgen --length 8 --count 2 --Uppercase" <<
		std::endl << std::endl << "Available Commands::" << std::endl << std::endl <<
		"--Length        Length of the password to create." << std::endl <<
		"--Count         Total number of passwords to create." << std::endl <<
		"--Uppercase     Include uppercase characters." << std::endl <<
		"--Lowercase     Include lowercase characters." << std::endl <<
		"--Digits        Include digits." << std::endl <<
		"--Symbols       Include special characters." << std::endl <<
		"--NoVowels      Remove all vowel characters." << std::endl <<
		"--N             Include line numbers." << std::endl <<
		"--Help          Display this help." << std::endl;
}

void _error(std::ostream &obj, int code){
	
	switch (code)
	{
	case 1:
		obj << "Length of generated password must be 6 or greater in length." <<
			std::endl << "Try --Length 8" << std::endl;
		break;
	case 2:
		obj << "Max length of generated password must not be above " <<
			MAX_PWS_LEN << std::endl;
		break;
	case 3:
		obj << "You need to include a password mask flag e.g. --Uppercase" << std::endl;
		break;
	case 4:
		obj << "Number of generated passwords must not exceed " << MAX_PASSWORDS << std::endl;
		break;
	case 5:
		obj << "The syntax of the command is incorrect. See --help for more information." << std::endl;
		break;
	case 6:
		obj << "Number of generated passwords must be greater then zero." << std::endl;
		break;
	case 7:
		obj << "Unknown command found exiting...." << std::endl;
		break;
	default:
		break;
	}
}

bool is_vowel(const unsigned char c){
	
	switch (c)
	{
	case 'A':
	case 'E':
	case 'I':
	case 'O':
	case 'U':
	case 'a':
	case 'e':
	case 'i':
	case 'o':
	case 'u':
		return true;
		break;
	default:
		break;
	}
	return false;
}

void StrUpper(std::string &src){
	//Convert a string to uppercase
	std::transform(src.begin(), src.end(), src.begin(), ::toupper);
}

std::string _getpassword(std::string mask, int length){
	//Random password generator
	unsigned int rnd;
	std::string rnd_password;
	std::random_device seeder;
	const auto seed = seeder.entropy() ? seeder() : std::time(nullptr);
	std::default_random_engine generator(
		static_cast<std::default_random_engine::result_type>(seed));

	for (auto len = 0; len < length; len++){
		std::uniform_int_distribution<int>distribution(0, pass_mask.length() - 1);
		rnd = distribution(generator);
		//Build random password.
		rnd_password += pass_mask[rnd];
	}
	return rnd_password;
}

int main(int argc, char *argv[]){
	int x = 1;
	std::string op;
	std::string StrPass;
	std::string sNumline;

	pws_len = 0;
	pws_count = 0;

	sUpper = false;
	sLower = false;
	sDigits = false;
	sSymbols = false;
	IncludeLineNo = false;
	RemoveVowels = false;

	if (argc == 1){
		_error(std::cout, 5);
		exit(EXIT_FAILURE);
	}
	//Check for help commmand
	if (argc == 2){
		op = argv[1];
		StrUpper(op);
		if (op == "--HELP"){
			_showhelp(std::cout);
		}
		exit(EXIT_FAILURE);
	}

	while (x < argc){
		if (argv[x][0] == '-'){
			op = argv[x];
			//Convert token to uppercase
			StrUpper(op);
			//Check token
			if (op == "--LENGTH"){
				//
				if (x + 1 < argc){
					pws_len = std::stoi(argv[x + 1]);
				}
			}else if (op == "--COUNT"){
				if (x + 1 < argc){
					pws_count = std::stoi(argv[x + 1]);
				}
			}else if (op == "--UPPERCASE"){
				sUpper = true;
			}else if (op == "--LOWERCASE"){
				sLower = true;
			}else if (op == "--DIGITS"){
				sDigits = true;
			}else if (op == "--SYMBOLS"){
				sSymbols = true;
			}else if (op == "--N"){
				IncludeLineNo = true;
			}else if (op == "--NOVOWELS"){
				RemoveVowels = true;
			}
			else{
				_error(std::cout, 7);
				exit(EXIT_FAILURE);
			}
		}
		x++;
	}
	//Fill in pass_mask
	if (sUpper){
		pass_mask.append(pUppercase);
	}
	if (sLower){
		pass_mask.append(pLowercase);
	}
	if (sDigits){
		pass_mask.append(pDigits);
	}
	if (sSymbols){
		pass_mask.append(pSymbol);
	}

	//Check lengths
	if (pws_count < MIN_PASSWORDS){
		_error(std::cout, 6);
		exit(EXIT_FAILURE);
	}
	
	if (pws_count > MAX_PASSWORDS){
		_error(std::cout, 4);
		exit(EXIT_FAILURE);
	}

	if (pws_len < MIN_PWS_LENGTH){
		_error(std::cout, 1);
		exit(EXIT_FAILURE);
	}

	if (pws_len > MAX_PWS_LEN){
		_error(std::cout, 2);
		exit(EXIT_FAILURE);
	}

	if (pass_mask.length() == 0){
		_error(std::cout, 3);
		exit(EXIT_FAILURE);
	}

	if (RemoveVowels){
		pass_mask = Remove_Vowels(pass_mask);
	}

	//Convert the number of passwords to a string
	sNumline = to_string(pws_count);

	//Show generated passwords.
	for (int n = 0; n < pws_count; n++){
		//Get new password.
		StrPass = _getpassword(pass_mask, pws_len);

		//Check if includeing line numbers.
		if (IncludeLineNo){
			std::cout << setfill('0') << setw(sNumline.length()) << (n + 1)
				<< " " << StrPass << std::endl;
		}
		else{
			//Output password.
			std::cout << StrPass << std::endl;
		}
	}

	//Clear up
	StrPass.clear();
	pass_mask.clear();

	return EXIT_SUCCESS;
}