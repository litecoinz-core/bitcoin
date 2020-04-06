// Copyright (c) 2013-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <clientversion.h>
#include <key.h>
#include <key_io.h>
#include <streams.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <test/setup_common.h>

#include <string>
#include <vector>

struct TestDerivation {
    std::string pub;
    std::string prv;
    unsigned int nChild;
};

struct TestVector {
    std::string strHexMaster;
    std::vector<TestDerivation> vDerive;

    explicit TestVector(std::string strHexMasterIn) : strHexMaster(strHexMasterIn) {}

    TestVector& operator()(std::string pub, std::string prv, unsigned int nChild) {
        vDerive.push_back(TestDerivation());
        TestDerivation &der = vDerive.back();
        der.pub = pub;
        der.prv = prv;
        der.nChild = nChild;
        return *this;
    }
};

TestVector test1 =
  TestVector("000102030405060708090a0b0c0d0e0f")
    ("xpub661MyMwAqRbcFDHxrQScxAhC6FvtPqShzp7YWUHDqoVg4cBXJ7ahm6JWz1auKFtSV5zqai9uSHvHs7HMPatnWND5smqtwz7ouwkEeMKuftz",
     "xprv9s21ZrQH143K2jDVkNucb2kTYE6PzNirdbBwi5scHTxhBorNkaGTDHz38hNdoDHE82DGEzVVHo3BmKDEYdJRG8yudLGZ3FfLQ8bafCwNNTD",
     0x80000000)
    ("xpub68SnViH9zkohB82fpNkGfRn2Ghc2VVgQcqKS24dFC9D3x7A5FikC6TL663vFZNNwhYRVgJLE4m8XAJaDsD6Cv2Jk4UcUtbLHbkQA4HVQ6rg",
     "xprv9uTS6CkGAPFPxdxCiMDGJHqHifmY62xZFcPqDgDddog55JpviBRwYf1cEneFu9nx5GyGMrCmNZJZS4iAwzgTx2KdSWW7251xcSZgiqfo1XN",
     1)
    ("xpub6A4T4xFvTaq7heDyVsEFNNkqeyYXtXHQfzQidJzyWFbZZ1MJxyJY1q28Gd4jLHPvYKvYUJLEDfGKDfRAqjUzmRTbT2HqJfr7rL1nQ5nec4C",
     "xprv9w56fSj2dDGpVA9WPqhF1Ep76wi3V4ZZJmV7pvbMwv4agD2ARRzHU2heRMn3BNScTecw4tHygnqBbhxJJpymMpMVuGXwk91mysXbE67HueF",
     0x80000002)
    ("xpub6Bj96oiXSMLvpXKPVBW6pMfFfsh667zs3xn3Sc67Dq9b5QbSP9EKoYZfsyMK2zMwjPRVQ5adg6RHRxWL7byTfjeuGzZrjP1ka8k9qpwg8JD",
     "xprv9xjnhJBdbyndc3EvP9y6TDiX7qrbgfH1gjrSeDgVfVccCcGHqbv5FkFC2g2kG77WxgHrPbCwMvgijzxJ5bWv3B2zdNxk9sFbnrj9oJ1WPWq",
     2)
    ("xpub6DeV2N5FqQNx5JZVr4eVPFY4gofhrei3DvEYWyMd4uNHgH6yEa9vV1gz4xELB7L2LQgHKbvAY7paRwKDg64JVpW5yVtKPaQr3V1C5tPqDBL",
     "xprv9zf8crYN12perpV2k37V27bL8mqDTBzBrhJwiax1WZqJoUmph2qfwDNWDhnnH67rewMqp2BXAhtYKmXrYyUyWQ96oPbqiYvPUVoU62frtRS",
     1000000000)
    ("xpub6GsV5gYUk6oq5Bj57SYs4ddyr6RuQtGBGdbzzrT7jfNW739KmAFNJG6ctGAfahoQjkHuDFqh4r8aaoeQus1kv69gVGRcqP8dzHSLyNMPbvA",
     "xprvA3t8gB1aujFXrhec1R1rhVhFJ4bR1RYKuQgQCU3WBKqXEEpBDcw7kTn92z9xk56K34ga3koUrQUfwCY3QsojzHCtroLDX4Cqj85SiZB6zXo",
     0);

TestVector test2 =
  TestVector("fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542")
    ("xpub661MyMwAqRbcFNyZziebbS7uqBSqzypFGsmkwV9Tq2pnocHEAzNkGw9WUtsJfGBnBr1kcCKbuvBckA3L2WdmDWEv998BPU1EibMGtehrjin",
     "xprv9s21ZrQH143K2tu6th7bEJBBH9cMbX6PuerA96jrGhHovox5dT4Vj8q2ddbUBhqhsaE86jM5VD71mvYXiBhY6G8LpCmJ6VxEB9rSWJdUsKx",
     0)
    ("xpub69hSpqsPLpwcKhjvvgh3ULczRuGR3s7nvCrvP3JcGakp9mw3PCf1wyrHq2ToLVT4b196HiwZnPiUevg4Ftc3vxJ1tfZGzZnNEMvMudpP2qH",
     "xprv9vi6RLLVWTPK7DfTpfA37CgFssRveQPwYywKaetziFDqGybtqfLmQBXoym6oigCgjiCTNErN6Rqx82Ho99nqcny3uEKzdJDpGtaGKjfjPyq",
     0xFFFFFFFF)
    ("xpub6A6C1o1q63B1NPu8ddHQzTKGfgFynZPbCBNHSZZ4WXFbtogqJqMjSGUBmRd6YCyv49fmKX2rWMQJfgHcAVQRkGY4tJFca6MYETfheP8touc",
     "xprv9w6qcHUwFfci9upfXbkQdKNY7eRVP6fjpxSgeB9SxBid21MgmJ3UtU9hvBbanm9HvpNtS4r2jC1AGPcsM3BHKbibXpynGesTFXop1qwAAjC",
     1)
    ("xpub6DPDDycdoXzMDuSRU6kiFMUYY6oWUWdV7zQnzUyDnUnKqT87s6jxastP6jToCAvsfL1vEXNpyWe23EUYu1sWtU7MSbMpA4Aj8qouVgeqLo9",
     "xprv9zPrpU5jyAS41RMxN5DhtDXoz4y253udkmVCC6ZcE9FLxenyKZRi35ZuFTRG4QQMei6i4hLPUBKkGzKRj4n9N9Q1h5EDLK8xnw7E13VNFmt",
     0xFFFFFFFE)
    ("xpub6EjmrqF5kfrEZmQdjRQpFTbFPodte5h8itwmN9Cu2MTK4CLMgQmDf2SaKeCRraLA1RcaK4gzGL4HWMSDjUxffktaeuyrYTnvz49jPfev4ZE",
     "xprvA1kRTKiBvJHwMHLAdPsotKeWqmoQEcyHMg2AZkoHU1vLBQ1D8sSy7E86UNVETjpLh86z1Xw81XQ9gL9WDwUtrYoj3mRnC9DRA1rWGJzTrox",
     2)
    ("xpub6H4FjuRmEFQ8c5zFYSNRncW5e9rQzZkimSCugSBqiJpp3gDW3UxaNnm6v1KUxUmkbcSk7mpQk9MnGL2Ki5JPCHYHovgdEiy8gXZNNrXWD1M",
     "xprvA44uLPtsPsqqPbunSQqRRUZM681vb72sQDHJt3nE9yHqAstMVweKpzSd4hMz6WARz6NJ8E2B4SAK6MFbDnvnzqXfpLjaAUXqFDBPYUAqNEJ",
     0);

TestVector test3 =
  TestVector("4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be")
    ("xpub661MyMwAqRbcEta6fL7LLtHQZUwmKBzGdyNH9ZVVbTUyxLBWKyxQfNwXAes9zLhh26y9iuAAQu2CgRZoEN8Mmp3f1kwtZspbr8uUvhjZiU5",
     "xprv9s21ZrQH143K2QVdZJaKykLg1T7GujGRGkSgMB5t37x15XrMnSeA7ad3KPeR9en884LCyxJZY6daqDV2SS6XnJmnoBNfx7XibGsBDRQ5Yek",
      0x80000000)
    ("xpub67urJva59BBhh54ez2EZ85MfhEDP6QdQZRBPWs8bYGo8qtgaRyxmg1u6Uqku3DXQvTi8fyyg2nutCpeC9qnLdghFmtL18NnRW8K88s9NTBU",
     "xprv9tvVuR3BJodQUazBszhYkwQw9CNtgwuZCCFniUiyywG9y6MRtSeX8Dacdbe8MQFDMgXo5WM8Y57t9dFpPv3Cuna62ZbVia1NTnVrKfZe2U2",
      0);

static void RunTest(const TestVector &test) {
    std::vector<unsigned char> seed = ParseHex(test.strHexMaster);
    CExtKey key;
    CExtPubKey pubkey;
    key.SetSeed(seed.data(), seed.size());
    pubkey = key.Neuter();
    for (const TestDerivation &derive : test.vDerive) {
        unsigned char data[74];
        key.Encode(data);
        pubkey.Encode(data);

        // Test private key
        BOOST_CHECK_EQUAL(EncodeExtKey(key), derive.prv);
        BOOST_CHECK(DecodeExtKey(derive.prv) == key); //ensure a base58 decoded key also matches

        // Test public key
        BOOST_CHECK_EQUAL(EncodeExtPubKey(pubkey), derive.pub);
        BOOST_CHECK(DecodeExtPubKey(derive.pub) == pubkey); //ensure a base58 decoded pubkey also matches

        // Derive new keys
        CExtKey keyNew;
        BOOST_CHECK(key.Derive(keyNew, derive.nChild));
        CExtPubKey pubkeyNew = keyNew.Neuter();
        if (!(derive.nChild & 0x80000000)) {
            // Compare with public derivation
            CExtPubKey pubkeyNew2;
            BOOST_CHECK(pubkey.Derive(pubkeyNew2, derive.nChild));
            BOOST_CHECK(pubkeyNew == pubkeyNew2);
        }
        key = keyNew;
        pubkey = pubkeyNew;

        CDataStream ssPub(SER_DISK, CLIENT_VERSION);
        ssPub << pubkeyNew;
        BOOST_CHECK(ssPub.size() == 75);

        CDataStream ssPriv(SER_DISK, CLIENT_VERSION);
        ssPriv << keyNew;
        BOOST_CHECK(ssPriv.size() == 75);

        CExtPubKey pubCheck;
        CExtKey privCheck;
        ssPub >> pubCheck;
        ssPriv >> privCheck;

        BOOST_CHECK(pubCheck == pubkeyNew);
        BOOST_CHECK(privCheck == keyNew);
    }
}

BOOST_FIXTURE_TEST_SUITE(bip32_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bip32_test1) {
    RunTest(test1);
}

BOOST_AUTO_TEST_CASE(bip32_test2) {
    RunTest(test2);
}

BOOST_AUTO_TEST_CASE(bip32_test3) {
    RunTest(test3);
}

BOOST_AUTO_TEST_SUITE_END()
