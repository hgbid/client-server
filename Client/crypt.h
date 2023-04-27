#pragma once
#include <string>

// cryptolib
#include <base64.h>
#include <rsa.h>
#include <cryptlib.h>
#include <hex.h>
#include <osrng.h>
#include <files.h>
#include <filters.h>
#include <aes.h>
#include <modes.h>
#include <crc.h>

using namespace std;
using namespace CryptoPP;

typedef struct keys {
    RSA::PrivateKey privKey;
    RSA::PublicKey pubKey;
    string privKeyBase64;
    string pubKeyBase64;
} keys;


void encryptAES(const string& plaintext, const string& key, string& ciphertext)
{
    string iv(AES::BLOCKSIZE, 0);
    AES::Encryption aesEncryption((CryptoPP::byte*)key.data(), AES::DEFAULT_KEYLENGTH);
    CBC_Mode_ExternalCipher::Encryption cbcEncryption(aesEncryption, (CryptoPP::byte*)iv.data());

    ciphertext.clear();
    StringSource(plaintext, true,
        new StreamTransformationFilter(cbcEncryption,
            new StringSink(ciphertext),
            StreamTransformationFilter::PKCS_PADDING));
}

void decryptAES(const string& ciphertext, const string& key, string& plaintext)
{
    std::string iv(AES::BLOCKSIZE, 0);
    AES::Decryption aesDecryption((CryptoPP::byte*)key.data(), AES::DEFAULT_KEYLENGTH);
    CBC_Mode_ExternalCipher::Decryption cbcDecryption(aesDecryption, (CryptoPP::byte*)iv.data());

    plaintext.clear();
    StringSource(ciphertext, true,
        new StreamTransformationFilter(cbcDecryption,
            new StringSink(plaintext)));
}

int encryptFile(string AESKey,string filename, string& fileContant) {
    // Open the file to send
    FILE* file;
    errno_t err = fopen_s(&file, filename.data(), "rb");
    if (err != 0) {
        cerr << "Could not open file: " << filename << endl;
        return 1;
    }
    string encoded, ciphertext;
    fseek(file, 0, SEEK_END);
    long fileSize = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = new char[fileSize];
    fread(buffer, 1, fileSize, file);
    fclose(file);

    string file_contant(buffer, fileSize);
    delete[] buffer;

    encryptAES(file_contant, AESKey, ciphertext);
    encoded.clear();
    StringSource ss2(ciphertext, true,
        new Base64Encoder(new StringSink(encoded)));
    fileContant = encoded;

    return 0;
}

string crc32(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        throw runtime_error("Could not open file");
    }
    string result="";
    CRC32 crc;
    FileSource(file, true, new HashFilter(crc, new HexEncoder(
          new StringSink(result))));

    return result;
}

string decryptAESKey(string enAESKey, keys cKeys) {
    AutoSeededRandomPool rng;
    string decoded, encryptedData;
    StringSource ss(enAESKey, true,
        new Base64Decoder(new StringSink(decoded)));
    encryptedData = decoded.substr(0, decoded.size() - 2);

    string decryptedData;
    RSAES_OAEP_SHA_Decryptor decryptor(cKeys.privKey);
    ArraySource(encryptedData, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(decryptedData)));

    return decryptedData;
}

keys generateKeys() {
    keys c_keys;
    AutoSeededRandomPool rng;

    // Generate the RSA key pair
    c_keys.privKey.GenerateRandomWithKeySize(rng, 1024);
    c_keys.pubKey.AssignFrom(c_keys.privKey);

    // Encode the RSA key pair to base64
    StringSink privSink(c_keys.privKeyBase64); // public key
    Base64Encoder privEncoder(new Redirector(privSink));
    c_keys.privKey.DEREncode(privEncoder);
    privEncoder.MessageEnd();

    StringSink pubSink(c_keys.pubKeyBase64); // private key
    Base64Encoder pubEncoder(new Redirector(pubSink));
    c_keys.pubKey.DEREncode(pubEncoder);
    pubEncoder.MessageEnd();

    //save private key in 'priv.key' file
    ofstream keyFile("priv.key");
    keyFile << c_keys.privKeyBase64; //private key
    keyFile.close();
    cout << "- Private RSA key saved into priv.key file" << endl;

    return c_keys;
}

keys loadPrivateKey() {
    keys c_keys;
    AutoSeededRandomPool rng;

    // Load private key from 'priv.key' file
    FileSource file("priv.key", true, new StringSink(c_keys.privKeyBase64));
    // Decode the base64-encoded private key
    StringSource ss(c_keys.privKeyBase64, true);
    Base64Decoder decoder;
    ss.TransferTo(decoder);
    decoder.MessageEnd();

    // Load the decoded private key into the RSA::PrivateKey object
    ByteQueue queue;
    decoder.TransferTo(queue);
    queue.MessageEnd();
    c_keys.privKey.Load(queue);

    return c_keys;
}