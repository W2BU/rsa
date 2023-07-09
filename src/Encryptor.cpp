
#include <string>
#include <vector>
#include "boost/multiprecision/cpp_int.hpp"

using uint128 = boost::multiprecision::uint128_t;
using CryptoString = std::vector<uint128>;

/*
    Encryptor class that uses public key given by RSA class to encrypt message
*/
class Encryptor
{
    private:
        PublicKey publicKey;
        std::string text;

    public:
        Encryptor(const PublicKey key);
        CryptoString encryptString(std::string inputString);
};

Encryptor::Encryptor(const PublicKey key)
{
    this->publicKey = key;
}

CryptoString Encryptor::encryptString(std::string inputString)
{
    CryptoString cypher;

    uint128 temp;
    for (size_t i = 0; i < inputString.size(); i++) {
        //  current char^e mod n
        temp = boost::multiprecision::powm((uint128)inputString[i], publicKey.e, publicKey.n);
        cypher.push_back(temp);
    }

    return cypher;
}