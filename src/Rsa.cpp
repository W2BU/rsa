#include <iostream>
#include <vector>
#include <string>
#include "Key.cpp"
#include "Encryptor.cpp"
#include "Decryptor.cpp"
#include "boost/multiprecision/cpp_int.hpp"

using uint128 = boost::multiprecision::uint128_t;
using CryptoString = std::vector<uint128>;

/*
    Class that implements RSA algorythm for message encryption and decryption
    Works for keys up to 128 bits
*/
class RSA
{
    private:
        PublicKey publicKey;
        PrivateKey privateKey;

        void calculatePrivateKey();
        //  sets the initial parameters for class
        void setParameters(const uint128 p, const uint128 q, const uint128 e);

        bool isPrime(uint128 number);

        //  uses Eucledean algorithm to calculate the greatest common divisor
        uint128 calculateGCD(uint128 a, uint128 b);

        //  uses Extended Eucledean algorithm to calculate private key
        uint128 extendedEuclidean(uint128 a, uint128 b, uint128* x, uint128* s);

    public:
        //  constructor
        RSA(uint128 p, uint128 q, uint128 e);

        //  public and private key getters
        const PublicKey getPublicKey();
        const PrivateKey getPrivateKey();

        //  encrypt string
        CryptoString encrypt(std::string str);

        //  decrypt string
        std::string decrypt(CryptoString encryptedStr);

        //  pretty print for CryptoString alias
        std::string cryptoToString(CryptoString encryptedStr);

        //  "<<" operator overload for pretty print
        friend std::ostream& operator <<(std::ostream& os, const RSA& rsa) {
            std::cout << "PUBLIC KEY\n";
            std::cout << "n = " << rsa.publicKey.n << "\n";
            std::cout << "e = " << rsa.publicKey.e << "\n";
            std::cout << "PRIVATE KEY\n";
            std::cout << "s = " << rsa.privateKey.d << "\n";
            std::cout << "p = " << rsa.privateKey.p << "\n";
            std::cout << "q = " << rsa.privateKey.q << "\n";

            return os;
        }
};

RSA::RSA(uint128 p = 0, uint128 q = 0, uint128 e = 0) {
    try {
        setParameters(p, q, e);
        calculatePrivateKey();
    } catch (std::exception &e) {
        throw;
        // std::cout << e.what();
    }
}

void RSA::setParameters(const uint128 p, const uint128 q, const uint128 e) {
    if (!isPrime(p) || !isPrime(q)) {
        throw std::exception("p or q is not a prime");
    } else if (!((e < p * q) && (e > 1))) {
        throw std::exception("e is not equal or less than p * q");
    } else if (calculateGCD(e, (p - 1) * (q - 1)) != 1) {
        throw std::exception("e and phi are not coprime");
    } else {
        this->privateKey.p = p;
        this->privateKey.q = q;
        this->privateKey.phi = (p - 1) * (q - 1);
        this->publicKey.e = e;
        this->publicKey.n = p * q;
    }
}

bool RSA::isPrime(uint128 number) {
    for (int divisor = 2; divisor < number; divisor++) {
        if ((number % divisor) == 0)
        return false;
    }
    return true;
}

uint128 RSA::calculateGCD(uint128 a, uint128 b) {
    if ((a == 0) || (b == 0)) return 0;

    uint128 q;
    uint128 r;

    do {
        q = a / b;
        r = a % b;

        a = b;
        b = r;
    } while (r != 0);

    return a;
}

uint128 RSA::extendedEuclidean(uint128 a, uint128 b, uint128* x, uint128* s) {
    if ((a == 0) || (b == 0)) return 0;

    uint128 q = 0;
    uint128 r = 0;

    q = a / b;
    r = a % b;

    uint128 x_tmp = *x;
    uint128 s_tmp = *s;

    if (r != 0) extendedEuclidean(b, r, &x_tmp, &s_tmp);

    if (r == 0) {
        *x = 0;
        *s = 1;
        return b;
    }

    *x = s_tmp;
    *s = x_tmp - (q * s_tmp);

    return b;
}

void RSA::calculatePrivateKey() {
    uint128 a = this->privateKey.phi;
    uint128 b = this->publicKey.e;

    uint128 d = 0;
    uint128 x = 0;

    extendedEuclidean(a, b, &x, &d);
    this->privateKey.d = d;
}

const PublicKey RSA::getPublicKey() {
    return publicKey;
}

const PrivateKey RSA::getPrivateKey() {
    return privateKey;
}

CryptoString RSA::encrypt(std::string str) {
    Encryptor encryptor(publicKey);
    CryptoString out = encryptor.encryptString(str);
    return out;
}

std::string RSA::decrypt(CryptoString encryptedStr) {
  Decryptor dec(privateKey);
  std::string res = dec.decryptString(encryptedStr);
  return res;
}

std::string RSA::cryptoToString(CryptoString encryptedStr) {
    std::string resultString = "";
    for (const auto& ch: encryptedStr) {
        resultString += ch.str() + " ";
    }
    return resultString;
}

