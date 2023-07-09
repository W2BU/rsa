
#include <string>
#include <vector>
#include "boost/multiprecision/cpp_int.hpp"

using uint128 = boost::multiprecision::uint128_t;
using CryptoString = std::vector<uint128>;

/*
    Decryptor class that uses private key given by RSA class to decrypt message
*/
class Decryptor
{
    private:
        PrivateKey privateKey;
        std::string text;

    public:
        Decryptor(const PrivateKey key);
        std::string decryptString(CryptoString inputString);
};

Decryptor::Decryptor(const PrivateKey key)
{
    this->privateKey = key;
}

std::string Decryptor::decryptString(CryptoString inputString)
{
    std::string resultString;

    uint128 temp;
    for (size_t i = 0; i < inputString.size(); i++) {
        //  current char^d mod phi
        temp = boost::multiprecision::powm(inputString[i], privateKey.d, privateKey.p * privateKey.q);
        resultString.push_back(temp.convert_to<char>());
    }

    return resultString;
}