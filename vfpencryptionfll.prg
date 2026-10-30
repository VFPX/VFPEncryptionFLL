*---This is intended to be a drop in replacement for vfpencryption.fll that has been a wonderful resource,
*---but is no longer supported by its donor and was built with superseded VC++ for 32-bit only.
*---This replacement should work without extra dependencies on x86 and x64 Vista and later because it uses Windows bcrypt.dll.

*---Uncomment GetSystem32 code at the end if not included elsewhere in project. Used to fully path System32 DECLAREs to prevent DLL sideloading.

*---this code relies heavily on Christof Wollenhaupt's excellent foxcryptong.prg whose code is replicated and edited for a few reasons:
*---to match VFPencryption better, especially padding, and (for example) because foxcryptong does a STRCONV() on hashes but VFPEncryption.fll does not,
*---also to allow cipher specification like the fll.
*---this code also ensures that expensive DECLARE DLLs only occur when actually needed.

*---Updated 2025-02-10 using Dmitriy Chunikhin's fork of foxcryptong, to add HMAC()

*---To use: SET PROC TO vfpencryptionfll.prg rather than SET LIBRARY TO vfpencryption.fll.

*vfpencryptionfll= 

*---NB: THE FOLLOWING _FLLCOMPATIBILITY SETTING DOES NOT WORK: left here for completeness. See below.
#Define _FLLCOMPATIBILITY .F.

*---While the formal AES spec says block length is always 16 bytes, VFPEncryption.fll's ENCRYPT()/DECRYPT() appears to default to 32 bytes for short plaintexts.
*---For plaintexts less than 16 bytes: the fll generates a 32-byte ciphertext unless you specify 16 byte blocksize.
*---Neither this PRG nor online AES resources can decrypt it, though the fll can.
*---If your existing code includes a 16-byte blocksize parameter or you want standard AES by default, or plaintext always exceeds 16 bytes, this is not an issue.
*---Otherwise the plan was that if fll compatibility is set, the default AES 16-byte blocksize is quietly reset to 32 bytes for short plaintexts, for a drop-in replacement.
*---note: not working, as bcrypt appears to disallow any AES blocklength except 16. See below.

#Define _STRIPPADDING .T.

*---This DECRYPT() does a better job of stripping padding than the fll that sometimes leaves spaces or chr(0).
*---If this is an issue (e.g. you have code that expects padding still there) then turn off _STRIPPADDING.

#Define BCRYPT_BLOCK_PADDING        0x00000001
#Define BCRYPT_BLOCK_NO_PADDING     0
#Define BCRYPT_PAD_NONE             0x00000001
#Define BCRYPT_PAD_PKCS1            0x00000002
#Define BCRYPT_PAD_OAEP             0x00000004
#Define BCRYPT_PAD_PSS              0x00000008
#Define BCRYPT_PAD_PKCS1_OPTIONAL_HASH_OID  0x00000010

#define BCRYPT_ALG_HANDLE_HMAC_FLAG 0x00000008

*#define STATUS_NOT_FOUND ((NTSTATUS)0xC0000225L)
*#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
*#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
*#define STATUS_INVALID_BUFFER_SIZE 0xc0000206
*#define STATUS_NOT_SUPPORTED: 0xc00000bb
*#define STATUS_INVALID_HANDLE 0xC0000008
*#define STATUS_INVALID_PARAMETER 0xc000000d

*!*	STATUS_SUCCESS
*!*	The function was successful.
*!*	STATUS_AUTH_TAG_MISMATCH
*!*	The computed authentication tag did not match the value supplied in the pPaddingInfo parameter.
*!*	STATUS_BUFFER_TOO_SMALL
*!*	The size specified by the cbOutput parameter is not large enough to hold the ciphertext.
*!*	STATUS_INVALID_BUFFER_SIZE
*!*	The cbInput parameter is not a multiple of the algorithm's block size, and the BCRYPT_BLOCK_PADDING flag was not specified in the dwFlags parameter.
*!*	STATUS_INVALID_HANDLE
*!*	The key handle in the hKey parameter is not valid.
*!*	STATUS_INVALID_PARAMETER
*!*	One or more parameters are not valid.
*!*	STATUS_NOT_SUPPORTED
*!*	The algorithm does not support decryption.

*************************************************************************************************************
Function HASH(tcData,nHashType,tcSecretkey)	&&HASH(cStringtohash,nHashType)
*************************************************************************************************************

*---the following is for VFP C++ Compiler = prompts obfuscation of variable names
*hash=
*tcdata=
*nHashtype=
*tcsecretkey=

*---replicates VFPEncryption Hash function.
*---NOTE: nHashtype 6 and 7 not implemented at this time

*!* IF tcSecretkey provided, performs HMAC Algorithm. Credit to Dmitrii Chunikhin

*!*	nHashType – The type of hash function to generate.

*!*	1 = SHA1 (a.k.a SHA160)
*!*	2 = SHA256
*!*	3 = SHA384
*!*	4 = SHA512 *Default
*!*	5 = MD5
*!*	6 = RIPEMD128
*!*	7 = RIPEMD160

Local tcAlgorithm,llHMAC
*tcAlgorithm=
*llHMAC=
tcAlgorithm=Getwordnum("SHA160 SHA256 SHA384 SHA512 MD5",Iif(Vartype(m.nHashType)="N" And Between(m.nHashType,1,5),m.nHashType,4))

llHMAC=Vartype(m.tcSecretKey)="C" AND Len(m.tcSecretKey) > 0

*--this is derived from the excellent foxcryptong
*--class not used directly because (for example) it does strconv on hash values that VFPEncryption does not,
*--also some extra functionality in VFP Encryption

*--------------------------------------------------------------------------------------
* Stop when we encounter a failure
*--------------------------------------------------------------------------------------
Local llOK,lnAlg
*llok=
*lnalg=
llOK = .T.

*--------------------------------------------------------------------------------------
* Get a handle to the hashing algorithm provider
*--------------------------------------------------------------------------------------
lnAlg = 0
*If m.llOK

llOK = BCryptOpenAlgorithmProvider( ;
			@lnAlg, ;
			Strconv(m.tcAlgorithm+Chr(0),5), ;
			NULL, ;
			Iif(m.llHMAC, BCRYPT_ALG_HANDLE_HMAC_FLAG, 0) ) == 0
			
			
*llOK = BCryptOpenAlgorithmProvider( ;
	@lnAlg, Strconv(m.tcAlgorithm+Chr(0),5), Null, 0 ) == 0
*EndIf

*--------------------------------------------------------------------------------------
* Determine how many bytes we need to store the hash object.
*--------------------------------------------------------------------------------------

If m.llOK
	Local lnSizeObj, lnData
	lnSizeObj = 0
	lnData = 0
	llOK = BCryptGetProperty( m.lnAlg, ;
		Strconv("ObjectLength"+Chr(0),5), @lnSizeObj, ;
		4, @lnData, 0 ) == 0
Endif

*--------------------------------------------------------------------------------------
* Determine length of hash value
* JR: Actually could avoid this call since we can easily compute hash length. Oh well
*--------------------------------------------------------------------------------------

If m.llOK
	Local lnSizeHash
	lnSizeHash = 0
	llOK = BCryptGetProperty( m.lnAlg, ;
		Strconv("HashDigestLength"+Chr(0),5), ;
		@lnSizeHash, 4, @lnData, 0 ) == 0
Endif

*--------------------------------------------------------------------------------------
* Allocate memory for the hash object
*--------------------------------------------------------------------------------------
Local lnHashObj
If m.llOK
	lnHashObj = HeapAlloc (GetProcessHeap (), 0, m.lnSizeObj)
	llOK = m.lnHashObj <> 0
Endif

*--------------------------------------------------------------------------------------
* Create the hash object
*--------------------------------------------------------------------------------------
Local lnHash
lnHash = 0
If m.llOK
	llOK = BCryptCreateHash( ;
			m.lnAlg, ;
			@lnHash, ;
			lnHashObj, ;
			m.lnSizeObj, ;
			Iif(m.llHMAC, m.tcSecretKey, NULL), ;
			Iif(m.llHMAC, Len(m.tcSecretKey), 0), ;
			0 ) == 0
	
	*llOK = BCryptCreateHash( m.lnAlg, @lnHash, ;
		lnHashObj, m.lnSizeObj, Null, 0, 0 ) == 0
Endif

*--------------------------------------------------------------------------------------
* To create the hash value we add data to the hash object. You can repeat this step
* as often as needed.
*--------------------------------------------------------------------------------------
If m.llOK
	llOK = BCryptHashData (m.lnHash, m.tcData, Len(m.tcData), 0) == 0
Endif

*--------------------------------------------------------------------------------------
* Signal the hash object that we are done. The algorithm then calculates the hash value
* and returns it.
*--------------------------------------------------------------------------------------
Local lcHash
If m.llOK
	lcHash = Space(m.lnSizeHash)
	llOK = BCryptFinishHash (m.lnHash, @lcHash, m.lnSizeHash, 0) == 0
Endif

*---JR vfpencryption doesn't strconv it...
*--------------------------------------------------------------------------------------
* Hashes are commonly viewed in the hex representation rather than the original
* binary form. As the final step we now convert the hash value into a hex string. Use
* STRCONV() if you do need a binary value, instead.
*--------------------------------------------------------------------------------------
*If m.llOK
*	lcHash = Strconv (m.lcHash, 15)
*EndIf

*--------------------------------------------------------------------------------------
* Cleanup
*--------------------------------------------------------------------------------------
If m.lnAlg != 0
	BCryptCloseAlgorithmProvider (m.lnAlg, 0)
Endif
If m.lnHash != 0
	BCryptDestroyHash (m.lnHash)
Endif
If Not Empty (m.lnHashObj)
	HeapFree (GetProcessHeap (), 0, m.lnHashObj)
Endif
If Not m.llOK
	lcHash = ""
Endif

Return m.lcHash


****************************************************************************************************
FUNCTION HMAC(tcData,tcSecretKey,nHashType)
****************************************************************************************************
*---Using Dmitrii Chunikhin's fork of FoxCryptoNG
RETURN Hash(m.tcData,m.nHashType,m.tcSecretkey)

**************************************************************************************************************************************************************
**************************************************************************************************************************************************************

**************************************************************************************************************************************************************
Function Encrypt(tcData,tcKey,tnEncryptionType,tnEncryptionMode,tnPaddingtype,tnKeysize,tnBlocksize,tcIV)
**************************************************************************************************************************************************************

*---Departures:
*---No Blowfish or TEA
*---No OFB Encryption mode

**VFPEncryption:
*!*	0 = Rijndael\AES 128 (requires a 16 character Key)
*!*	1 = Rijndael\AES 192 (requires a 24 character Key)
*!*	2 = Rijndael\AES 256 (requires a 32 character Key) *Default
*!*	4 = Blowfish (key between 1 and 56 characters)
*!*	8 = TEA (requires a 16 character Key)
*!*	1024 = RC4 (Key can be any length)

*tcData=
*tcKey=
*tnEncryptionType=
*tnEncryptionMode=
*tnPaddingtype=
*tnKeysize=
*tnBlocksize=
*tcIV=

Local tcAlgorithm,liBlockLength,liKeylen,llUseIV
*tcalgorithm=
*liblocklength=
*likeylen=
*lluseIV=

Do Case

Case Vartype(m.tnEncryptionType) !="N"	&&apply default
	tcAlgorithm="AES"
	liKeylen=32
	#If _FLLCOMPATIBILITY
		liBlockLength=IIF(LEN(m.tcdata)<16,32,16)	&&the dll seems to use 32-byte blocks for short plaintexts
	#Else
		liBlockLength=16
	#Endif

Case Between(m.tnEncryptionType,0,2)	&&AES
	tcAlgorithm="AES"
	liKeylen=Icase(m.tnEncryptionType=0,16,m.tnEncryptionType=1,24,32)
	#If _FLLCOMPATIBILITY
		liBlockLength=IIF(LEN(m.tcdata)<16,32,16)	&&the dll seems to use 32-byte blocks for short plaintexts
	#Else
		liBlockLength=16
	#Endif
*CASE m.tnEncryptionType=4
*---Windows BCrypt doesn't process Blowfish

*CASE m.tnEncryptionType=8
*---Windows BCrypt doesn't process TEA

Case m.tnEncryptionType=1024
*---included for completeness, but RC4 is insecure. Use AES.
	tcAlgorithm="RC4"
	liKeylen=0	&&key can be any length
	liBlockLength=0

Otherwise
	tcAlgorithm="AES"
	liKeylen=32
	#If _FLLCOMPATIBILITY
		liBlockLength=IIF(LEN(m.tcdata)<16,32,16)	&&the dll seems to use 32-byte blocks for short plaintexts
	#Else
		liBlockLength=16
	#Endif
Endcase

*---Get the keylen correct- as bcrypt uses it to determine encryption level
*---from experimentation it appears that VFPEncryption replicates a short password as required
*---to reach correct key length.

Local liActualKeyLen
liActualKeyLen=Len(m.tcKey)

*---actually can't allow user to mess with keysize... keylen is determined by EncryptionType

*If Empty(m.tnKeysize)
*Else
*	liKeylen=m.tnKeysize
*Endif

*If Empty(m.liKeylen) Or m.liActualKeyLen=m.liKeylen
IF m.liActualKeyLen !=m.liKeylen
*Else
	tcKey=Left(Iif(liActualKeyLen>m.liKeylen,m.tcKey,Replicate(m.tcKey,Ceiling(m.liKeylen/m.liActualKeyLen))),m.liKeylen)
Endif

*--------------------------------------------------------------------------------------
* Stop when we encounter a failure
*--------------------------------------------------------------------------------------
Local llOK
llOK = .T.

*--------------------------------------------------------------------------------------
* Get a handle to the algorithm provider
*--------------------------------------------------------------------------------------
Local lnAlg
lnAlg = 0
If m.llOK
	llOK = BCryptOpenAlgorithmProvider( ;
		@lnAlg, Strconv(m.tcAlgorithm+Chr(0),5), Null, 0 ) == 0
Endif


******************************************************************************************************
*---VFPEncryption:
*!*	nEncryptionMode – There are three different modes available for the each of the encryption types listed above. They include: Electronic Code Book (ECB), Cipher Block Chaining (CBC), Cipher Feedback Block (CFB), and Output Feedback Block. The nEncryptionMode parameter does not apply to RC4 encryption (nEncryptionType = 1024).

*!*	0 = ECB *Default
*!*	1 = CBC
*!*	2 = CFB
*!*	3 = OFB

*---chainingmode can be set in alg or key.
If m.llOK
	Local lcChainingMode
	Do Case

	Case m.tcAlgorithm !="AES"
*---only need chaining mode for chained encryption

	Case Vartype(m.tnEncryptionMode) !="N" Or Empty(m.tnEncryptionMode)
		lcChainingMode="ChainingModeECB"

	Case m.tnEncryptionMode=1
		lcChainingMode="ChainingModeCBC"
		llUseIV=.t.
				
	Case m.tnEncryptionMode=2
		lcChainingMode="ChainingModeCFB"
		llUseIV=.t.
		
*---OFB appears not to be an option in bcrypt
*CASE m.tnEncryptionMode=3
*	lcChainingMode="ChainingModeOFB"
	Otherwise
		lcChainingMode="ChainingModeECB"
	Endcase

	If Empty(m.lcChainingMode)
	Else
*MS Learn: When setting the value for the property BCRYPT_CHAINING_MODE, the pbInput parameter is unbounded by cbInput. The caller needs to ensure a valid null-terminated Unicode string is provided.
		lcChainingmode=Strconv(m.lcChainingMode+Chr(0),5)
		llOK = BCryptSetProperty_String(m.lnAlg,Strconv("ChainingMode"+Chr(0),5),m.lcChainingmode,LEN(m.lcChainingmode),0)=0
		*llOK = BCryptSetProperty_String(m.lnAlg,Strconv("ChainingMode"+Chr(0),5),Strconv(m.lcChainingMode,5)+Chr(0),0,0)=0
		
*Confirm setting
*!*	Declare Long BCryptGetProperty In BCrypt.Dll as BCryptGetProperty_String;
*!*		Long hObject, ;
*!*		String pszProperty, ;
*!*		string @pbInput, ;
*!*		Long cbOutput, ;
*!*		Long @pcbResult, ;
*!*		Long dwFlags
*!*		lcVal=SPACE(200)
*!*		lndata=0
*!*		llOK = BCryptGetProperty_string( m.lnalg, ;
*!*			Strconv("ChainingMode"+Chr(0),5), @lcVal, ;
*!*			200, @lnData, 0 ) == 0
*!*		lcVal=STRCONV(m.lcval,6)
*!*		? LEFT(m.lcVal,ATC(CHR(0),m.lcval))
*!*		*ChainingModeECB
	Endif
Endif

*--------------------------------------------------------------------------------------
* Turn the key into a symmetric key object that we can pass to the encryption funtion.
*--------------------------------------------------------------------------------------
Local lnKey
lnKey = 0
If m.llOK
	llOK = BCryptGenerateSymmetricKey ( ;
		m.lnAlg, @lnKey, Null, 0, @tcKey, Len (m.tcKey), 0) == 0
Endif

***************************************************************************************************************
*   JR THIS THROWS AN ERROR TRYING TO SET BLOCKSIZE via integer or charttobin. Parameter should be ignored.
***************************************************************************************************************

*!*	*---set blocksize...
*!*	If m.llOK And m.liBlockLength>0

*!*		If Vartype(m.tnBlocksize) ="N" And m.liBlockLength != m.tnBlocksize
*!*			liBlockLength=m.tnBlocksize
*!*		Endif

*!*	*!*		*--------------------------------------------------------------------------------------
*!*	*!*		* Tried this too: Allocate memory for the setting pointer
*!*	*!*		*--------------------------------------------------------------------------------------
*!*	*!*		Local lnHashObj
*!*	*!*		If m.llOK
*!*	*!*			lnHashObj = HeapAlloc (GetProcessHeap (), 0, 4)
*!*	*!*			llOK = m.lnHashObj <> 0
*!*	*!*		EndIf
*!*	*!*
*!*	*!*		IF m.llOK
*!*	*	Local lcBintoc
*!*	*	lcBintoc=BinToC(m.liBlockLength,4)
*!*	*		SYS(2600,m.lnhashobj,4,m.lcBintoc)
*!*	*		llOK = BCryptSetProperty_string(lnKey,Strconv("BlockLength"+Chr(0),5),m.lcBintoc,4,0)=0
*!*	*!*		endif
*!*	Endif

*---Block length alwsys 16 for AES, but easy to check at this point if needed...
*!*	If m.llOK
*!*		local lnData
*!*		liBlockLength = 0
*!*		lnData = 0
*!*		llOK = BCryptGetProperty( m.lnAlg, ;
*!*			Strconv("BlockLength"+Chr(0),5), @liBlockLength, ;
*!*			4, @lnData, 0 ) == 0
*!*	ENDIF

*---Padding:
******************************************************************************************************
*!*	VFPEncryption:
*!* nPaddingMode – For Block Ciphers the cStringtoEncrypt is padded to a multiple of the block size for the algorithm. Setting this parameter allows you to specify how this padding is done.
*!*	0 = Zeroes (NULLs) *Default
*!*	1 = Spaces (blanks)
*!*	2 = PKCS7
*!*	3 = ANSI X.923
*!*	4 = ISO 10126

*---bcrypt theoretically allows some padding definitions via a passed structure-
*---but bcrypt doesn't have the same or all the options in VFPEncryption and structures are no fun in VFP. This will do:

If m.llOK And m.liBlockLength>0
	LOCAL lipad
	*lipad=
*---to match, this code needs to as well...
	liPad=m.liBlockLength-Len(m.tcData)%m.liBlockLength	&&can never be 0; will be 16 for a perfect length, so need to add a block

	Do Case
	Case Empty(m.tnPaddingtype)
		tcData=m.tcData+Replicate(Chr(0),m.liPad)

	Case m.tnPaddingtype=1
		tcData=m.tcData+Space(m.liPad)

	Case m.tnPaddingtype=2
*---need to add at least 1 char padding...
		Local lcChar
		lcChar=Chr(m.liPad)
		tcData=m.tcData+Replicate(m.lcChar,m.liPad)

	Case m.tnPaddingtype=3
*In ANSI X.923 bytes filled with zeros are padded and the last byte defines the padding boundaries or the number of padded bytes.
*---need to add at least 1 char padding...
		tcData=m.tcData+Replicate(Chr(0),m.liPad-1)+Chr(m.liPad)


	Case m.tnPaddingtype=4
*ISO 10126 specifies that the padding should be done at the end of that last block with random bytes, and the padding boundary should be specified by the last byte.
*---need to add at least 1 char padding...
		Local licounter,liRandoms,lcRandom
		*licounter=
		*liRandoms=
		*lcRandom=
		
		liRandoms=m.liPad-1

		lcRandom=""
		If m.liRandoms>0
			For licounter=1 To m.liRandoms
				lcRandom=m.lcRandom+Chr(Rand()*255)
			Endfor
		Endif

		tcData=m.tcData+m.lcRandom+Chr(m.liPad)
	Otherwise
		tcData=m.tcData+Replicate(Chr(0),m.liPad)
	Endcase
Endif

*--------------------------------------------------------------------------------------
* We handle a block ciphers. The size of encrypted data is a multiple of the block size
* which is based on the key length. We let the algorithm provider determine the actual
* length.
*--------------------------------------------------------------------------------------
Local lnSize,lcIV,llPrefixIV
*lnSize=
*lcIV=
*llPrefixIV=

If m.llOK
	lnSize = 0
	*If Pcount() > 7	or m.llUseIV	&&was 3, but VFPEncryption has more parameters!
	IF m.llUseIV	
		*--if CBC and no IV passed, create one now
		IF EMPTY(m.tcIV)
			tcIV=SPACE(16)
			=CocreateGUID(@m.tcIV)
			llPrefixIV=.t.
		ENDIF
		
		lcIV=m.tcIV
					
		llOK = BCryptEncrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, @m.lcIV, Len(m.lcIV), Null, 0, ;
			@lnSize,BCRYPT_BLOCK_NO_PADDING) == 0
	Else
		llOK = BCryptEncrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, Null, 0, Null, 0, ;
			@lnSize,BCRYPT_BLOCK_NO_PADDING) == 0
	Endif
Endif


*--------------------------------------------------------------------------------------
* Now we can finally encrypt data
*--------------------------------------------------------------------------------------
Local lcEncrypted
If m.llOK
	lcEncrypted = Space (m.lnSize)
	If  m.llUseIV	&&Pcount() > 7
		lcIV = m.tcIV
		llOK = BCryptEncrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, @m.lcIV, Len(m.lcIV), @lcEncrypted, ;
			Len(m.lcEncrypted), @lnSize,BCRYPT_BLOCK_NO_PADDING) == 0
	Else
		llOK = BCryptEncrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, Null, 0, @lcEncrypted, ;
			Len(m.lcEncrypted), @lnSize,BCRYPT_BLOCK_NO_PADDING) == 0
	Endif
Endif

*--------------------------------------------------------------------------------------
* Properly close any open handle. We return an empty varbinary value if any error
* occurred.
*--------------------------------------------------------------------------------------
If m.lnKey != 0
	BCryptDestroyKey (m.lnKey)
Endif
If m.lnAlg != 0
	BCryptCloseAlgorithmProvider (m.lnAlg, 0)
Endif
If Not m.llOK
	lcEncrypted = ""
Endif

IF m.llPrefixIV	&&m.llUseIV AND ! EMPTY(m.lcPrefix)
	RETURN m.tcIV+m.lcEncrypted
ELSE
	Return m.lcEncrypted
ENDIF

***************************************************************************************************************************************************************************
Function DECRYPT(tcData,tcKey,tnEncryptionType,tnEncryptionMode,tnPaddingtype,tnKeysize,tnBlocksize,tcIV)

*---vfpencryption specifies encryption level, but
*---bcrypt uses key length

*---Departures:
*---No Blowfish or TEA
*---No OFB Encryption mode

**VFPEncryption:
*!*	0 = Rijndael\AES 128 (requires a 16 character Key)
*!*	1 = Rijndael\AES 192 (requires a 24 character Key)
*!*	2 = Rijndael\AES 256 (requires a 32 character Key) *Default
*!*	4 = Blowfish (key between 1 and 56 characters)
*!*	8 = TEA (requires a 16 character Key)
*!*	1024 = RC4 (Key can be any length)


*tcData=
*tcKey=
*tnEncryptionType=
*tnEncryptionMode=
*tnPaddingtype=
*tnKeysize=
*tnBlocksize=
*tcIV=

Local tcAlgorithm,liBlockLength,liKeylen,llUseIV
*tcAlgorithm=
*liBlockLength=
*liKeylen=
*llUseIV=

Do Case

Case Vartype(m.tnEncryptionType) !="N"	&&apply default
	tcAlgorithm="AES"
	liKeylen=32
	#If _FLLCOMPATIBILITY
		liBlockLength=IIF(LEN(m.tcdata)<16,32,16)	&&the dll seems to use 32-byte blocks for short plaintexts
	#Else
		liBlockLength=16
	#Endif

Case Between(m.tnEncryptionType,0,2)	&&AES
	tcAlgorithm="AES"
	liKeylen=Icase(m.tnEncryptionType=0,16,m.tnEncryptionType=1,24,32)
	#If _FLLCOMPATIBILITY
		liBlockLength=IIF(LEN(m.tcdata)<16,32,16)	&&the dll seems to use 32-byte blocks for short plaintexts
	#Else
		liBlockLength=16
	#Endif

*CASE m.tnEncryptionType=4
*---Windows BCrypt doesn't process Blowfish

*CASE m.tnEncryptionType=8
*---Windows BCrypt doesn't process TEA

Case m.tnEncryptionType=1024
*---included for completeness, but RC4 is insecure. Use AES.
	tcAlgorithm="RC4"
	liKeylen=0	&&key can be any length
	liBlockLength=0

Otherwise
	tcAlgorithm="AES"
	liKeylen=32
	#If _FLLCOMPATIBILITY
		liBlockLength=IIF(LEN(m.tcdata)<16,32,16)	&&the dll seems to use 32-byte blocks for short plaintexts
	#Else
		liBlockLength=16
	#Endif
Endcase

*---Get the keylen correct- as bcrypt uses it to determine encryption level
*---from experimentation it appears that VFPEncryption repeats a short password as required
*---to reach correct key length.

Local liActualKeyLen
*liActualKeyLen=
liActualKeyLen=Len(m.tcKey)

*---actually can't allow user to mess with keysize... keylen is determined by EncryptionType. Ignore parameter

*If Empty(m.tnKeysize)
*Else
*	liKeylen=m.tnKeysize
*Endif

IF m.liActualKeyLen !=m.liKeylen
	tcKey=Left(Iif(liActualKeyLen>m.liKeylen,m.tcKey,Replicate(m.tcKey,Ceiling(m.liKeylen/m.liActualKeyLen))),m.liKeylen)
Endif

*========================================================================================
* Decrypts data with a symmetric block based algorithm.
*========================================================================================
*Procedure Decrypt_SymmetricBlock (tcAlgorithm, tcData, tcKey, tcIV)

*--------------------------------------------------------------------------------------
* Stop when we encounter a failure
*--------------------------------------------------------------------------------------
Local llOK
llOK = .T.

*--------------------------------------------------------------------------------------
* Get a handle to the requested algorithm provider
*--------------------------------------------------------------------------------------
Local lnAlg
lnAlg = 0
If m.llOK
	llOK = BCryptOpenAlgorithmProvider( ;
		@lnAlg, Strconv(m.tcAlgorithm+Chr(0),5), Null, 0 ) == 0
Endif

******************************************************************************************************
*---VFPEncryption:
*!*	nEncryptionMode – There are three different modes available for the each of the encryption types listed above. They include: Electronic Code Book (ECB), Cipher Block Chaining (CBC), Cipher Feedback Block (CFB), and Output Feedback Block. The nEncryptionMode parameter does not apply to RC4 encryption (nEncryptionType = 1024).

*!*	0 = ECB *Default
*!*	1 = CBC
*!*	2 = CFB
*!*	3 = OFB

*---chainingmode can be set in alg or key.
If m.llOK
	Local lcChainingMode
	*lcChainingmode=
	Do Case

	Case m.tcAlgorithm !="AES"
*---only need chaining mode for chained encryption

	Case Vartype(m.tnEncryptionMode) !="N"
		lcChainingMode="ChainingModeECB"
	
	Case m.tnEncryptionMode=1
		lcChainingMode="ChainingModeCBC"
		llUseIV=.t.

	Case m.tnEncryptionMode=2
		lcChainingMode="ChainingModeCFB"
		llUseIV=.t.
		
*---OFB appears not to be an option in bcrypt
*CASE m.tnEncryptionMode=3
*	lcChainingMode="ChainingModeOFB"
	Otherwise
		lcChainingMode="ChainingModeECB"
	Endcase

	If Empty(m.lcChainingMode)
	Else
*MS Learn: When setting the value for the property BCRYPT_CHAINING_MODE, the pbInput parameter is unbounded by cbInput. The caller needs to ensure a valid null-terminated Unicode string is provided.
		lcChainingmode=Strconv(m.lcChainingMode+Chr(0),5)
		llOK = BCryptSetProperty_String(m.lnAlg,Strconv("ChainingMode"+Chr(0),5),m.lcChainingmode,LEN(m.lcChainingmode),0)=0
		*llOK = BCryptSetProperty_String(m.lnAlg,Strconv("ChainingMode",5)+Chr(0),Strconv(m.lcChainingMode,5)+Chr(0),0,0)=0

*!*	*Confirm setting
*!*		Declare Long BCryptGetProperty In BCrypt.Dll as BCryptGetProperty_String;
*!*		Long hObject, ;
*!*		String pszProperty, ;
*!*		string @pbInput, ;
*!*		Long cbOutput, ;
*!*		Long @pcbResult, ;
*!*		Long dwFlags
*!*		
*!*		lcVal=SPACE(200)
*!*		lndata=0
*!*		llOK = BCryptGetProperty_string( m.lnalg, ;
*!*			Strconv("ChainingMode"+Chr(0),5), @lcVal, ;
*!*			200, @lnData, 0 ) == 0
*!*		lcVal=STRCONV(m.lcval,6)
*!*		? LEFT(m.lcVal,ATC(CHR(0),m.lcval))
*!*		*ChainingModeECB
	Endif
Endif

*---do we need to peel off the IV?
IF m.llUseIV AND EMPTY(m.tcIV)
	tcIV=LEFT(m.tcdata,16)
	tcData=SUBSTR(m.tcdata,17)
ENDIF

*--------------------------------------------------------------------------------------
* Turn the key into a symmetric key object that we can pass to the encryption funtion.
*--------------------------------------------------------------------------------------
Local lnKey
lnKey = 0
If m.llOK
	llOK = BCryptGenerateSymmetricKey ( ;
		m.lnAlg, @lnKey, Null, 0, @tcKey, Len (m.tcKey), 0) == 0
Endif

***************************************************************************************************************
*   JR THIS THROWS AN ERROR TRYING TO SET BLOCKSIZE via integer or charttobin. Parameter needs to be ignored
***************************************************************************************************************

*---set blocksize...
*!*	If m.llOK And m.liBlockLength>0

*!*		If Vartype(m.tnBlocksize) ="N" And m.liBlockLength != m.tnBlocksize
*!*			liBlockLength=m.tnBlocksize
*!*		Endif

*!*	*!*		*--------------------------------------------------------------------------------------
*!*	*!*		* Tried this too: Allocate memory for the setting pointer
*!*	*!*		*--------------------------------------------------------------------------------------
*!*	*!*		Local lnHashObj
*!*	*!*		If m.llOK
*!*	*!*			lnHashObj = HeapAlloc (GetProcessHeap (), 0, 4)
*!*	*!*			llOK = m.lnHashObj <> 0
*!*	*!*		EndIf
*!*	*!*
*!*	*!*		IF m.llOK
*!*	*	Local lcBintoc
*!*	*	lcBintoc=BinToC(m.liBlockLength,4)
*!*	*		SYS(2600,m.lnhashobj,4,m.lcBintoc)
*!*	*		llOK = BCryptSetProperty_string(lnKey,Strconv("BlockLength"+Chr(0),5),m.lcBintoc,4,0)=0
*!*	*!*		endif
*!*	Endif

*---Block length alwsys 16 for AES, but easy to check at this point if needed...
*!*	If m.llOK
*!*		local lnData
*!*		liBlockLength = 0
*!*		lnData = 0
*!*		llOK = BCryptGetProperty( m.lnAlg, ;
*!*			Strconv("BlockLength"+Chr(0),5), @liBlockLength, ;
*!*			4, @lnData, 0 ) == 0
*!*	ENDIF

*--------------------------------------------------------------------------------------
* We ask the algorithm provider for the length of our data.
*--------------------------------------------------------------------------------------
Local lnSize,lcIV

If m.llOK
	lnSize = 0
	If m.llUseIV	&&Pcount() > 7	&&means IV provided...
		lcIV = m.tcIV
		llOK = BCryptDecrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, @m.lcIV, Len(m.lcIV), Null, 0, ;
			@lnSize, BCRYPT_BLOCK_NO_PADDING) == 0
	Else
		
		
		llOK = BCryptDecrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, Null, 0, Null, 0, ;
			@lnSize, BCRYPT_BLOCK_NO_PADDING) == 0
	Endif
Endif

*--------------------------------------------------------------------------------------
* Now we can finally decrypt data.
*--------------------------------------------------------------------------------------
Local lcDecrypted
If m.llOK
	lcDecrypted = Space (m.lnSize)

	IF m.llUseIV	&&Pcount() > 7
		*--there's always an IV- either passed, or peeled off
		lcIV=m.tcIV
		
		llOK = BCryptDecrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, @lcIV, Len(m.lcIV), @lcDecrypted, ;
			Len(m.lcDecrypted), @lnSize,BCRYPT_BLOCK_NO_PADDING) == 0
	Else
		llOK = BCryptDecrypt ( ;
			m.lnKey, m.tcData, Len(m.tcData), Null, Null, 0, @lcDecrypted, ;
			Len(m.lcDecrypted), @lnSize,BCRYPT_BLOCK_NO_PADDING) == 0
	Endif
Endif

*--------------------------------------------------------------------------------------
* Properly close any open handle. We return an empty varbinary value if any error
* occurred.
*--------------------------------------------------------------------------------------
If m.lnKey != 0
	BCryptDestroyKey (m.lnKey)
Endif
If m.lnAlg != 0
	BCryptCloseAlgorithmProvider (m.lnAlg, 0)
Endif
If Not m.llOK
	lcDecrypted = ""
Endif

*---padding...
#If _STRIPPADDING
	Do Case
	Case Empty(m.tnPaddingtype)
		lcDecrypted =Rtrim(m.lcDecrypted,Chr(0))

	Case m.tnPaddingtype=1
		lcDecrypted=Rtrim(m.lcDecrypted)

	Case Between(m.tnPaddingtype,2,4)
*---last byte provides the padding length...
		Local liPad
		liPad=Asc(Right(m.lcDecrypted,1))
		If Empty(m.liPad)
			liPad=m.liBlockLength
		Endif
		m.lcDecrypted=Left(m.lcDecrypted,Len(m.lcDecrypted)-m.liPad)
	Otherwise
		m.lcDecrypted=Rtrim(m.lcDecrypted,Chr(0))
	Endcase
#Endif

Return m.lcDecrypted

********************************************************************************************************************************************************
FUNCTION EncryptFile(tcFiletoEncrypt,tcDestinationFile,tcKey,tnEncryptionType,tnEncryptionMode,tnPaddingtype,tnKeysize,tnBlocksize,tcIV)
********************************************************************************************************************************************************
*---per VFPEncryption documentation: fullpath filenames are needed. Add error handling as required!

*tcFiletoEncrypt=
*tcDestinationFile=
*tcKey=
*tnEncryptionType=
*tnEncryptionMode=
*tnPaddingtype=
*tnKeysize=
*tnBlocksize=
*tcIV=

LOCAL lcData
TRY
	lcData=FILETOSTR(m.tcFiletoEncrypt)
CATCH
	lcData=""
ENDTRY

TRY
	lcData=Encrypt(m.lcData,m.tcKey,m.tnEncryptionType,m.tnEncryptionMode,m.tnPaddingtype,m.tnKeysize,m.tnBlocksize,m.tcIV)
CATCH
	lcData=""
ENDTRY

=STRTOFILE(m.lcData,m.tcDestinationFile,1)

********************************************************************************************************************************************************
FUNCTION Decryptfile(tcEncryptedFile,tcDestinationFile,cDestinationFile,tcKey,tnEncryptionType,tnEncryptionMode,tnPaddingtype,tnKeysize,tnBlocksize,tcIV)
********************************************************************************************************************************************************
*---per VFPEncryption documentation: fullpath filenames are needed. Add error handling as required!

*tcEncryptedFile=
*tcDestinationFile=
*tcKey=
*tnEncryptionType=
*tnEncryptionMode=
*tnPaddingtype=
*tnKeysize=
*tnBlocksize=
*tcIV=

LOCAL lcData
TRY
	lcData=FILETOSTR(m.tcEncryptedFile)
CATCH
	lcData=""
ENDTRY

TRY
	lcData=Decrypt(m.lcData,m.tcKey,m.tnEncryptionType,m.tnEncryptionMode,m.tnPaddingtype,m.tnKeysize,m.tnBlocksize,m.tcIV)
CATCH
	lcData=""
ENDTRY

=STRTOFILE(m.lcData,m.tcDestinationFile,1)

********************************************************************************************************************************************************
FUNCTION Hashfile(tcFiletoHash,tnHashtype)
********************************************************************************************************************************************************
*---per VFPEncryption documentation: fullpath filenames are needed. Add error handling as required!

*tcFilename=
*tnHashtype=

LOCAL lcData
TRY
	lcData=FILETOSTR(m.tcFiletoHash)
CATCH
	lcData=""
ENDTRY

TRY
	lcData=Hash(m.lcData,m.tnHashtype)
CATCH
	lcData=""
ENDTRY

RETURN m.lcData


*--------------------Declares done this way to only use as required

Function BCryptOpenAlgorithmProvider(tnphAlgorithm,tcpszAlgId,tcpszImplementation,tndwFlags)
*---they all start with this, so define all API to create and destroy the cryptography objects

*tnphAlgorithm=
*tcpszAlgId=
*tcpszImplementation=
*tndwFlags

LOCAL lcBcrypt
*lcBcrypt=
*lcBcrypt="BCrypt.Dll"
lcBcrypt=getsystem32()+"BCrypt.Dll"

Declare Long BCryptOpenAlgorithmProvider ;
	in (m.lcBcrypt) ;
	Long @phAlgorithm, ;
	String pszAlgId, ;
	String pszImplementation, ;
	Long dwFlags

Declare Long BCryptGetProperty In (m.lcBcrypt) ;
	Long hObject, ;
	String pszProperty, ;
	Long @pbOutput, ;
	Long cbOutput, ;
	Long @pcbResult, ;
	Long dwFlags

*Declare Long BCryptGetProperty In (m.lcBcrypt) as BCryptGetProperty_String;
	Long hObject, ;
	String pszProperty, ;
	string @pbInput, ;
	Long cbOutput, ;
	Long @pcbResult, ;
	Long dwFlags
	
*!*	Declare Long BCryptSetProperty In (m.lcBcrypt) ;
*!*		long hObject,;
*!*		string pszProperty,;
*!*		long @pbInput,;
*!*		long cbInput,;
*!*		long dwFlags

Declare Long BCryptSetProperty In (m.lcBcrypt) As BCryptSetProperty_String ;
	long hObject,;
	string pszProperty,;
	string @pbInput,;
	long cbInput,;
	long dwFlags

Declare Long BCryptCloseAlgorithmProvider ;
	in (m.lcBcrypt) ;
	Long hAlgorithm, ;
	Long dwFlags

*--------------------------------------------------------------------------------------
* Generic Windows memory management functions for Hash
*--------------------------------------------------------------------------------------
Declare Long HeapAlloc In win32api ;
	Long hHeap, ;
	Long dwFlags, ;
	Long dwBytes

Declare Long GetProcessHeap In win32api

Declare Long HeapFree In win32api ;
	Long hHeap, ;
	Long dwFlags, ;
	Long lpMem

Return BCryptOpenAlgorithmProvider(@tnphAlgorithm,m.tcpszAlgId,m.tcpszImplementation,m.tndwFlags)

Function BCryptCreateHash(tnhAlgorithm,tnphHash,tnpbHashObject,tncbHashObject,tcpbSecret,tncbSecret,tndwFlags)

*---hashing:  other API to create and process hash, as these are always needed

*tnhAlgorithm=
*tnphHash=
*tnpbHashObject=
*tncbHashObject=
*tcpbSecret=
*tncbSecret=
*tndwFlags=

LOCAL lcBcrypt
*lcBcrypt=
lcBcrypt=getsystem32()+"BCrypt.Dll"
*lcBcrypt="BCrypt.Dll"

Declare Long BCryptCreateHash In (m.lcBcrypt) ;
	Long hAlgorithm, ;
	Long @phHash, ;
	Long pbHashObject, ;
	Long cbHashObject, ;
	String pbSecret, ;
	Long cbSecret, ;
	Long dwFlags

Declare Long BCryptHashData In (m.lcBcrypt) ;
	Long hHash, ;
	String pbInput, ;
	Long cbInput, ;
	Long dwFlags

Declare Long BCryptFinishHash In (m.lcBcrypt) ;
	Long hHash, ;
	String @pbOutput, ;
	Long cbOutput, ;
	Long dwFlags

Declare Long BCryptDestroyHash In (m.lcBcrypt) ;
	Long hHash


Return BCryptCreateHash(m.tnhAlgorithm,@tnphHash,m.tnpbHashObject,m.tncbHashObject,m.tcpbSecret,m.tncbSecret,m.tndwFlags)

Function BCryptGenerateSymmetricKey(tnhAlgorithm,tnphkey,tcpbKeyObject,tncbKeyObject,tcpbSecret,tncbSecret,tndwFlags)

*tnhAlgorithm=
*tnphkey=
*tcpbKeyObject=
*tncbKeyObject=
*tcpbSecret=
*tncbSecret=
*tndwFlags=

LOCAL lcBcrypt
*lcBcrypt=
*lcBcrypt="BCrypt.Dll"
lcBcrypt=getsystem32()+"BCrypt.Dll"

Declare Long BCryptGenerateSymmetricKey In (m.lcBcrypt) ;
	Long hAlgorithm, ;
	Long @phKey, ;
	String pbKeyObject, ;
	Long cbKeyObject, ;
	String pbSecret, ;
	Long cbSecret, ;
	Long dwFlags

Declare Long BCryptDestroyKey In (m.lcBcrypt) ;
	Long hKey

Return BCryptGenerateSymmetricKey(tnhAlgorithm,@tnphkey,m.tcpbKeyObject,m.tncbKeyObject,@tcpbSecret,m.tncbSecret,m.tndwFlags)

Function BCryptEncrypt(tnhkey,tcpbInput,tncbInput,tcpPaddingInfo,tcpbIV,tncbIV,tcpbOutput,tncbOutput,tnpcbResult,tndwFlags)

*tnhkey=
*tcpbInput=
*tncbInput=
*tcpPaddingInfo=
*tcpbIV,tncbIV=
*tcpbOutput=
*tncbOutput=
*tnpcbResult=
*tndwFlags=

LOCAL lcBcrypt
*lcBcrypt=
lcBcrypt=getsystem32()+"BCrypt.Dll"

Declare Long BCryptEncrypt In (m.lcBcrypt) ;
	Long hKey, ;
	String pbInput, ;
	Long cbInput, ;
	String pPaddingInfo, ;
	String @pbIV, ;
	Long cbIV, ;
	String @pbOutput, ;
	Long cbOutput, ;
	Long @pcbResult, ;
	Long dwFlags

Return  BCryptEncrypt(m.tnhkey,m.tcpbInput,m.tncbInput,m.tcpPaddingInfo,@tcpbIV,m.tncbIV,@tcpbOutput,m.tncbOutput,@tnpcbResult,m.tndwFlags)

Function BCryptDecrypt(tnhkey,tcpbInput,tncbInput,tcpPaddingInfo,tcpbIV,tncbIV,tcpbOutput,tncbOutput,tnpcbResult,tndwFlags)
*tnhkey=
*tcpbInput=
*tncbInput=
*tcpPaddingInfo=
*tcpbIV=
*tncbIV=
*tcpbOutput=
*tncbOutput=
*tnpcbResult=
*tndwFlags=

LOCAL lcBcrypt
*lcBcrypt=
*lcBcrypt="BCrypt.Dll"
lcBcrypt=getsystem32()+"BCrypt.Dll"

Declare Long BCryptDecrypt In (m.lcBcrypt) ;
	Long hKey, ;
	String pbInput, ;
	Long cbInput, ;
	String pPaddingInfo, ;
	String @pbIV, ;
	Long cbIV, ;
	String @pbOutput, ;
	Long cbOutput, ;
	Long @pcbResult, ;
	Long dwFlags
Return BCryptDecrypt(m.tnhkey,m.tcpbInput,m.tncbInput,m.tcpPaddingInfo,@tcpbIV,m.tncbIV,@tcpbOutput,m.tncbOutput,@tnpcbResult,m.tndwFlags)

Function CoCreateGuid(tcStrucGUID)

Declare Integer CoCreateGuid In (Getsystem32()+"Ole32.Dll") String @cGUIDStruc
*Declare Integer StringFromGUID2 ;
IN Ole32.Dll ;
STRING cGUIDStruc, ;
STRING @cGUID, ;
LONG nSize
Return CoCreateGuid(@tcStrucGUID)
ENDFUNC

*!*	********************************************************************************************
*!*	Function GetSystem32()
*!*	********************************************************************************************
*!*	If Pemstatus(_vfp,"csystem32",5)
*!*		Return _vfp.csystem32
*!*	Else
*!*		Local lcFolder,liLen
*!*		lcFolder=Space(500)

*!*		If Vartype(_WIN64) !="L" Or ! _WIN64
*!*	*---not VFPA64
*!*			Declare Integer GetSystemWow64Directory In Win32API As GETSYSTEMX String @, Integer
*!*			liLen=GETSYSTEMX(@lcFolder, 500)
*!*		Endif

*!*		If Empty(m.liLen)
*!*	*---VFPA64 or VFP9/A on 32-bit OS
*!*			Declare Integer GetSystemDirectory In Win32API As GETSYSTEMX String @, Integer
*!*			liLen=GETSYSTEMX(@lcFolder, 500)
*!*		Endif

*!*		Clear Dlls GETSYSTEMX

*!*		lcFolder=Addbs(Left(m.lcFolder,m.liLen))

*!*		=AddProperty(_vfp,"csystem32",m.lcFolder)

*!*		Return m.lcFolder
*!*	Endif
