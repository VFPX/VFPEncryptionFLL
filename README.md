# VFPEncryptionFLL

[![ChangeLog](https://img.shields.io/github/last-commit/VFPX/VFPEncryptionFLL?path=ChangeLog.md&label=Latest%20Release)](ChangeLog.md)

Project Manager: John Ryan

This code is intended as a drop-in replacement for the excellent vfpencryption.fll (and vfpencryption71.fll) that have been a wonderful resource. However, they are no longer supported by their author (Craig Boyd), they rely on obsolete VC++ libraries, and they are incompatible with x64 VFP development.

This PRG uses the Windows BCrypt API so it is compatible with both x86 and x64 development and can be included in your project with no other dependencies.

To use this PRG, replace:

```
SET LIBRARY TO vfpencryption.fll
```

with:

```
SET PROCEDURE TO vfpencryptionfll.prg
```

Departures from vfpencryption.fll:

* Bcrypt does not include Blowfish, so neither does this PRG.

* CRC functions and GenerateKey() not implemented; see SYS(2007) and GUID functions.

* Not all encryption modes are supported. Notations made in the documentation below.

* The FLL's DECRYPT() function  did not always strip off block padding, but this PRG does. If your code expects to strip padding, you can change:

    ```
    #Define _STRIPPADDING .T.
    ```
    
    to:
    
    ```
    #Define _STRIPPADDING .F.
    ```
    
    and DECRYPT() will not strip the padding.

* If you specify an encryption mode that needs an IV but do not provide it, **the PRG's Encrypt() generates a GUID IV and prefixes it to the ciphertext**. Decrypt() without IV will strip off the first block and use it as IV for the rest. Cryptographically the IV does not need to be secret, so this is safe.

Please note: if you are encrypting binary material, the FLL's nPaddingMode 0 (the default) and 1 were problematic, as binary plaintext could end with a chr(0) or space character so you can't safely rtrim. The same applies to this PRG. To be safe, ISO 10126 padding (mode 4) is properly implemented by this PRG and is the most random.

## Function ENCRYPT()

Signature:

Encrypt(cStringtoEncrypt, cSecretKey[, nEncryptionType[, nEncryptionMode[, nPaddingType[, nKeySize[, nBlockSize[, cIV]]]]]])

Parameters:

* cStringtoEncrypt: A plain text string you want to have encrypted, such as "Hello World!"

* cSecretKey: A plain text string that is the key you want used during encryption, such as "My_SeCrEt_KeY". The FLL corrected keylength for AES, and so does this PRG.

* nEncryptionType: There are currently 3 ~~5~~ types of encryption available. The value of this parameter determines the type of encryption used and how long your key should be. A single character in Visual FoxPro is equal to 1 byte or 8 bits. So an encryption algorithm requiring a 128-bit key would need a key of 16 characters (16 x 8 = 128).

    * 0 = Rijndael\AES 128 (requires a 16 character key)
    * 1 = Rijndael\AES 192 (requires a 24 character key)
    * 2 = Rijndael\AES 256 (requires a 32 character key) * Default
    * ~~4 = Blowfish (key between 1 and 56 characters)~~
    * ~~8 = TEA (requires a 16 character Key)~~
    * 1024 = RC4 (Key can be any length) – INSECURE, do not use

* nEncryptionMode: There are three different modes available for the each of the encryption types listed above. They include Electronic Code Book (ECB), Cipher Block Chaining (CBC), Cipher Feedback Block (CFB), and ~~Output Feedback Block~~. The nEncryptionMode parameter does not apply to RC4 encryption (nEncryptionType = 1024).

    * 0 = ECB * Default
    * 1 = CBC
    * 2 = CFB
    * ~~3 = OFB~~

* nPaddingMode: For Block Ciphers, cStringtoEncrypt is padded to a multiple of the block size for the algorithm. Setting this parameter allows you to specify how this padding is done.

    * 0 = Zeroes (NULLs) * Default
    * 1 = Spaces (blanks)
    * 2 = PKCS7
    * 3 = ANSI X.923
    * 4 = ISO 10126

* ~~nKeySize: The size of the cSecretKey in bytes (characters).~~ Cannot be changed in AES, do not use.

* ~~nBlockSize: The block size the nEncryptionType should use.~~ Cannot be changed in AES, do not use.

* cIV: The Initialization Vector (IV) that CBC, CFB, and OFB modes should use. This IV should be 16 bytes for AES. **If you do not specify an IV for a mode that requires an IV, the PRG will generate a GUID IV and prefix it to the ciphertext.** Cryptographically the IV does not need to be secret, so this is safe.

Return Value:

Character: the encrypted form of cStringtoEncrypt.

Remarks:

When saving the return value of Encrypt() to a field in a table, remember that Visual FoxPro will append blanks to the end of the string in order to fill the character field to its designated length. This can cause problems when decrypting the data as the spaces will be considered part of the encrypted string. **Craig Boyd suggested** placing a single CHR(0) at the end of the encrypted string when saving it to the table. Then when decrypting the data just the portion prior to the CHR(0) can be sent into the Decrypt() function. This does not apply when using RC4 encryption (nEncryptionType = 1024).
**Or you can change character fields to Varchar (binary). Or you might be able to rely on known block length (16 bytes) to truncate to proper length.**

## Function DECRYPT()

Signature:

Decrypt(cEncryptString, cSecretKey[, nDecryptionType[, nDecryptionMode[, nPaddingType[, nKeySize[, nBlockSize[, cIV]]]]]])
Parameters:

* cEncryptedString: A string that has been encrypted using the Encrypt() function.

* cSecretKey: A plain text string that is the same key that you used when you encrypted the data using the Encrypt function, such as “My_SeCrEt_KeY”. The FLL corrected keylength for AES, and so does this PRG.

* nEncryptionType: There are currently 3 ~~5~~ types of encryption available and they correspond to the same ones available in Encrypt(). A single character in Visual FoxPro is equal to 1 byte or 8 bits. So an encryption algorithm requiring a 128-bit key would need a key of 16 characters (16 x 8 = 128).

    * 0 = Rijndael\AES 128 (requires a 16 character key)
    * 1 = Rijndael\AES 192 (requires a 24 character key)
    * 2 = Rijndael\AES 256 (requires a 32 character key) * Default
    * ~~4 = Blowfish (key between 1 and 56 characters)~~
    * ~~8 = TEA (requires a 16 character Key)~~
    * 1024 = RC4 (Key can be any length) – INSECURE, do not use

* nEncryptionMode: There are three different modes available for the each of the encryption types listed above. They include Electronic Code Book (ECB), Cipher Block Chaining (CBC), Cipher Feedback Block (CFB), and ~~Output Feedback Block~~. The nEncryptionMode parameter does not apply to RC4 encryption (nEncryptionType = 1024).

    * 0 = ECB * Default
    * 1 = CBC
    * 2 = CFB
    * ~~3 = OFB~~

* nPaddingMode: For Block Ciphers, cStringtoEncrypt is padded to a multiple of the block size for the algorithm. Setting this parameter allows you to specify how this padding is done.

    * 0 = Zeroes (NULLs) * Default
    * 1 = Spaces (blanks)
    * 2 = PKCS7
    * 3 = ANSI X.923
    * 4 = ISO 10126

* ~~nKeySize: The size of the cSecretKey in bytes (characters).~~ Cannot be changed in AES, do not use.

* ~~nBlockSize: The block size the nEncryptionType should use.~~ Cannot be changed in AES, do not use.

* cIV: The Initialization Vector (IV) that CBC, CFB, and OFB modes should use. This IV should be 16 bytes for AES. **If it is not provided for a mode that needs an IV, the first block is stripped off as the IV and used to decrypt the rest.**

Return Value:

Character: the decrypted form of cEncryptedString.

Remarks:

The PRG automatically strips off the padding for your specified nPaddingMode, but the FLL did not always. If your existing code expects to strip off padding, you can change the #Define _STRIPPADDING .T. at the start of the PRG to #Define _STRIPPADDING .F. and the padding will not be stripped by DECRYPT().

## Function ENCRYPTFILE()

Signature:

EncryptFile(cFiletoEncrypt, cDestinationFile, cSecretKey[, nEncryptionType[, nEncryptionMode[, nPaddingType[, nKeySize[, nBlockSize[, cIV]]]]]])

Parameters:

* cFiletoEncrypt: A plain text string that is the full path to the file you wish to be encrypted, such as "C:\SensitiveInfo.doc".

* cDestinationFile: A plain text string that is the full path to an encrypted file you wish to have created on disk, such as "C:\EncryptedInfo.doc". If this file doesn't exist, it will be created.

* cSecretKey: A plain text string that is the key you want used during encryption, such as "My_SeCrEt_KeY". The FLL corrected keylength for AES, and so does this PRG.

* nEncryptionType: There are currently 3 ~~5~~ types of encryption available. The value of this parameter determines the type of encryption used and how long your key should be. A single character in Visual FoxPro is equal to 1 byte or 8 bits. So an encryption algorithm requiring a 128-bit key would need a key of 16 characters (16 x 8 = 128).

    * 0 = Rijndael\AES 128 (requires a 16 character key)
    * 1 = Rijndael\AES 192 (requires a 24 character key)
    * 2 = Rijndael\AES 256 (requires a 32 character key) * Default
    * ~~4 = Blowfish (key between 1 and 56 characters)~~
    * ~~8 = TEA (requires a 16 character Key)~~
    * 1024 = RC4 (Key can be any length) – INSECURE, do not use

* nEncryptionMode: There are three different modes available for the each of the encryption types listed above. They include Electronic Code Book (ECB), Cipher Block Chaining (CBC), Cipher Feedback Block (CFB), and ~~Output Feedback Block~~. The nEncryptionMode parameter does not apply to RC4 encryption (nEncryptionType = 1024).

    * 0 = ECB * Default
    * 1 = CBC
    * 2 = CFB
    * ~~3 = OFB~~

* nPaddingMode: For Block Ciphers, cStringtoEncrypt is padded to a multiple of the block size for the algorithm. Setting this parameter allows you to specify how this padding is done.

    * 0 = Zeroes (NULLs) * Default
    * 1 = Spaces (blanks)
    * 2 = PKCS7
    * 3 = ANSI X.923
    * 4 = ISO 10126

* ~~nKeySize: The size of the cSecretKey in bytes (characters).~~ Cannot be changed in AES, do not use.

* ~~nBlockSize: The block size the nEncryptionType should use.~~ Cannot be changed in AES, do not use.

* cIV: The Initialization Vector (IV) that CBC, CFB, and OFB modes should use. This IV should be 16 bytes for AES. **If you do not specify an IV for a mode that requires an IV, the PRG will generate a GUID IV and prefix it to the ciphertext.**

Return Value:

None

## Function DECRYPTFILE()

Signature:

DecryptFile(cEncryptedFile, cDestinationFile, cSecretKey[, nDecryptionType[, nDecryptionMode[, nPaddingType[, nKeySize[, nBlockSize[, cIV]]]]]])

Parameters:

* cEncyptedFile: A plain text string that is the full path to the file you wish to be decrypted, such as "C:\EncryptedInfo.doc".

* cDestinationFile: A plain text string that is the full path to a decrypted file you wish to have created on disk, such as "C:\SensitiveInfo.doc". If this file doesn't exist, it will be created.

* cSecretKey: A plain text string that is the same key that you used when you encrypted the data using the EncryptFile function, such as "My_SeCrEt_KeY". The FLL corrected keylength for AES, and so does this PRG.

* nEncryptionType: There are currently 3 ~~5~~ types of encryption available. The value of this parameter determines the type of encryption used and how long your key should be. A single character in Visual FoxPro is equal to 1 byte or 8 bits. So an encryption algorithm requiring a 128-bit key would need a key of 16 characters (16 x 8 = 128).

    * 0 = Rijndael\AES 128 (requires a 16 character key)
    * 1 = Rijndael\AES 192 (requires a 24 character key)
    * 2 = Rijndael\AES 256 (requires a 32 character key) * Default
    * ~~4 = Blowfish (key between 1 and 56 characters)~~
    * ~~8 = TEA (requires a 16 character Key)~~
    * 1024 = RC4 (Key can be any length) – INSECURE, do not use

* nEncryptionMode: There are three different modes available for the each of the encryption types listed above. They include Electronic Code Book (ECB), Cipher Block Chaining (CBC), Cipher Feedback Block (CFB), and ~~Output Feedback Block~~. The nEncryptionMode parameter does not apply to RC4 encryption (nEncryptionType = 1024).

    * 0 = ECB * Default
    * 1 = CBC
    * 2 = CFB
    * ~~3 = OFB~~

* nPaddingMode: For Block Ciphers, cStringtoEncrypt is padded to a multiple of the block size for the algorithm. Setting this parameter allows you to specify how this padding is done.

    * 0 = Zeroes (NULLs) * Default
    * 1 = Spaces (blanks)
    * 2 = PKCS7
    * 3 = ANSI X.923
    * 4 = ISO 10126

* ~~nKeySize: The size of the cSecretKey in bytes (characters).~~ Cannot be changed in AES, do not use.

* ~~nBlockSize: The block size the nEncryptionType should use.~~ Cannot be changed in AES, do not use.

* cIV: The Initialization Vector (IV) that CBC, CFB, and OFB modes should use. This IV should be 16 bytes for AES. **If it is not provided for a mode that needs an IV, the first block is stripped off as the IV and used to decrypt the rest.**

Return Value:

None

## Function HASH()

Signature:

Hash(cStringtoHash[, nHashType])

Parameters:

* cStringtoHash: A plain text string you wish to have hashed.

* nHashType: The type of hash function to generate. There are currently 5 ~~7~~ different hash functions supported:

    * 1 = SHA1 (a.k.a SHA160)
    * 2 = SHA256
    * 3 = SHA384
    * 4 = SHA512 *Default
    * 5 = MD5
    * ~~6 = RIPEMD128~~
    * ~~7 = RIPEMD160~~

Return Value:

Binary Character: the hash for cStringtoHash.

Remarks:
The hash is returned as a series of binary characters. However, it is more common to see hashes in a hexBinary format. This can be accomplished in Visual FoxPro by taking the return of the Hash() function and sending it in as a parameter to the STRCONV() function. For example:

```
?STRCONV(Hash("Some String"), 15) && hexBinary Hash
```

## Function HASHFILE()

Signature:

HashFile(cFileName[, nHashType])

Parameters:

* cFileName: The full path and name of an existing file you wish to generate a message digest for.

* nHashType: The type of hash function to generate. There are currently 5 ~~7~~ different hash functions supported:

    * 1 = SHA1 (a.k.a SHA160)
    * 2 = SHA256
    * 3 = SHA384
    * 4 = SHA512 *Default
    * 5 = MD5
    * ~~6 = RIPEMD128~~
    * ~~7 = RIPEMD160~~

Return Value:

Binary Character Data: the hash for cFileName.

Remarks:

The hash is returned as a series of binary characters. However, it is more common to see hashes in a hexBinary format. This can be accomplished in Visual FoxPro by taking the return of the HashFile() function and sending it in as a parameter to the STRCONV() function. For example:

```
?STRCONV(HashFile("C:\MyFile.txt"), 15) && hexBinary Hash 
```

~~## Function HASHRECORD()~~ 

~~Signature:~~

~~HashRecord(cAlias[, nHashType[,lIncludeMemos]])~~

~~Parameters:~~

~~* cAlias: The table alias containing the record to be hashed.~~
~~* nHashType: The type of hash function to generate. There are currently 5 ~~7~~ different hash functions supported:~~

 ~~* 1 = SHA1 (a.k.a SHA160)~~
 ~~* 2 = SHA256~~
 ~~* 3 = SHA384~~
 ~~* 4 = SHA512 *Default~~
 ~~* 5 = MD5~~
 ~~* 6 = RIPEMD128~~
 ~~* 7 = RIPEMD160~~

~~* lIncludeMemos: Flag determining whether Memo fields should be included when generating the message digest. .T. = Include Memo Fields, .F. = Exclude Memo Fields~~

~~Return Value:~~

~~Binary Character: the hash for the current record in cAlias.~~

~~Remarks:~~

~~The hash is returned as a series of binary characters. However, it is more common to see hashes in a hexBinary format. This can be accomplished in Visual FoxPro by taking the return of the HashRecord() function and sending it in as a parameter to the STRCONV() function. For example:~~

~~```~~
~~?STRCONV(HashRecord("MyTable", 5, .T.), 15) && hexBinary Hash~~ 
~~```~~

## Function HMAC()

Signature:

HMAC(cStringtoHash, cSecretKey[, nHashType])

Parameters:

* cStringtoHash: A plain text string you wish to have a keyed Hash Message Authentication Code (HMAC) generated from.

* cSecretKey: A plain text string that is the Key you want used during generation of the keyed HMAC.

* nHashType: The type of hash function to generate. There are currently 5 ~~7~~ different hash functions supported:

    * 1 = SHA1 (a.k.a SHA160)
    * 2 = SHA256
    * 3 = SHA384
    * 4 = SHA512 *Default
    * 5 = MD5
    * ~~6 = RIPEMD128~~
    * ~~7 = RIPEMD160~~

Return Value:

Binary Character: the HMAC for the given cStringtoHash and cSecretKey.

Remarks:

The HMAC is returned as a series of binary characters. However, it is more common to see HMACs in a hexBinary format. This can be
accomplished in Visual FoxPro by taking the return of the HMAC() function and sending it in as a parameter to STRCONV(cReturn, 15).

## Helping with this project

See [How to contribute to VFPEncryptionFLL](.github/CONTRIBUTING.md) for details on how to help with this project.

## Releases

The latest version is 2026.10.30.

See the [change log](ChangeLog.md) for release information.
