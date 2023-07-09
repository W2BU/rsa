#include "boost/multiprecision/cpp_int.hpp"

using uint128 = boost::multiprecision::uint128_t;

struct PublicKey
{
    uint128 n;    // modulus
    uint128 e;    // exponent
};

struct PrivateKey
{
    uint128 p;    // prime 1
    uint128 q;    // prime 2
    uint128 phi;  // (p - 1) * (q - 1)
    uint128 d;    // e * d − 1 is a multiple of phi(n)
};