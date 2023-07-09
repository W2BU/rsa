#include <iostream>
#include "Rsa.cpp"
#include "boost/multiprecision/cpp_int.hpp"
#include "boost/algorithm/string.hpp"

int main()
{
	try {
		std::vector<std::string> initNums = {"0", "0", "0"};
		std::string line;
		std::cout << "Enter p, q and e separated by space\n";
		std::getline(std::cin, line);
		boost::split(initNums, line, boost::is_any_of(" "));
		RSA rsa(uint128(initNums.at(0)), uint128(initNums.at(1)), uint128(initNums.at(2)));
		// RSA rsa(11, 13, 23);
		std::cout << rsa;
		std::string input;
		std::cout << "Enter a message\n";
		std::getline(std::cin, input);
		CryptoString out = rsa.encrypt(input);
		std::string result = rsa.decrypt(out);
		std::cout << "Input Message:  " << input << "\n"
				<< "Encrypted message:  " << rsa.cryptoToString(out) << "\n"
				<< "Decrypted message:  " << result << "\n";
	} catch (std::exception& e) {
		std::cout << "RSA exception thrown\n";
		std::cout << e.what();
	}
	std::getchar();
	return 0;
}