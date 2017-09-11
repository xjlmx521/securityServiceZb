
#include "../include/zb_common.h"
#ifdef ZB_SECURITY
#include "../../platform/chip_826x/includes/aes_ccm_826x.h"


/*Input: An integer challenge len which is the length in bits of the challenge required. challenge len shall be 80.
Actions: Select a statistically unique and unpredictable bit string Challenge of length challenge len. It is acceptable
to use a random or a pseudo random string. If a pseudo random string is used, it shall be generated using one
of the procedures of Annex A.4 or of an ANSI X9 approved standard. If a pseudo random number is used,
optional information to store with the challenge are the seed values and the particular pseudo random
generation method used. Storing this optional information helps allow auditing of the challenge generation
process.
If a pseudo random generation method is used, the seed values used in the generation of Challenge may be
determined by internal means, be supplied by the caller, or both - this is an implementation choice.
Output: The bit string Challenge.*/

_CODE_SS_ void ss_tlChallengeGen(u8 *data, u8 len){
	for(u8 i=0;i<len;i++){
		data[i] = rand();
	}
}

_CODE_SS_ u8 ss_ccmEncryption(u8 *key, u8 *nonce, u8 nwkHdrLen, u8 *nwkHdr, u8 srcMsgLen, u8 *srcMsg){
	u8 mic[4];
	aes_ccmAuthTran(4, key, nonce, srcMsg, srcMsgLen, nwkHdr, nwkHdrLen, mic);
	aes_ccmEncTran(4, key, nonce, srcMsg, srcMsgLen, nwkHdr, nwkHdrLen, mic);
	memcpy((srcMsg+srcMsgLen),mic,4);
	return (4 + srcMsgLen);
}


_CODE_SS_ u8 ss_ccmDecryption(u8 *key, u8 *nonce, u8 nwkHdrLen, u8 *nwkHdr, u8 srcMsgLen, u8 *srcMsg)
{
	u8 *mic = NULL;

	mic = srcMsg + srcMsgLen - 4;

	srcMsgLen -= 4;

	aes_ccmDecTran(4, key, nonce, srcMsg, srcMsgLen, nwkHdr, nwkHdrLen, mic);
	u8 ret = aes_ccmDecAuthTran(4, key, nonce, srcMsg, srcMsgLen, nwkHdr, nwkHdrLen, mic);
	return ret;
}


_CODE_SS_ u8 tl_cryHashFunction(u8* input, u8 inputLen, u8 *output){
	u8 cipherIn[AES_BLOCK_SIZE];
	u32 i=0,j=0;

	memset(output,0,AES_BLOCK_SIZE);

	while(i<inputLen){
		cipherIn[j++]=input[i++];

		if( j>= AES_BLOCK_SIZE){
			hwAes_encrypt(output, cipherIn, output);
			for(j=0;j<AES_BLOCK_SIZE;j++) output[j] ^= cipherIn[j];
			j=0;
		}
	}

	cipherIn[j++] = 0x80;

	while(j!=(AES_BLOCK_SIZE - 2)){
		if(j>=AES_BLOCK_SIZE){
			hwAes_encrypt(output, cipherIn, output);
			for(j=0;j<AES_BLOCK_SIZE;j++) output[j] ^= cipherIn[j];
			j=0;
		}
		cipherIn[j++] = 0;
	}//end while

	cipherIn[j++] = ((inputLen*8)>>8) & 0xff;
	cipherIn[j] = ((inputLen*8)>>0) &0xff;

	hwAes_encrypt(output, cipherIn, output);
	for(j=0;j<AES_BLOCK_SIZE;j++) output[j] ^= cipherIn[j];


	return RET_OK;
}


_CODE_SS_ void ss_ttlMAC(u8 len, u8 *input, u8 *key, u8 *hashOut){
	u8	hasIn[2*AES_BLOCK_SIZE];
	int		i;

	u8	temBuff[128];
	u8	ipad=0x36;
	u8	opad=0x5c;

	for(i=0;i<AES_BLOCK_SIZE;i++)	hasIn[i] = key[i]^opad;

	for(i=0;i<AES_BLOCK_SIZE;i++)	temBuff[i] = key[i]^ipad;

	for(i=0;i<len;i++) temBuff[i+AES_BLOCK_SIZE] = input[i];


	tl_cryHashFunction(temBuff,AES_BLOCK_SIZE+len,hasIn+AES_BLOCK_SIZE);

	tl_cryHashFunction(hasIn,AES_BLOCK_SIZE*2,hashOut);

}

_CODE_SS_ u8 ss_keyHash(u8 *padV, u8 *key, u8 *hashOut){
	ss_ttlMAC(1,padV,key,hashOut);
	return RET_OK;

}

#endif //ZB_SECURITY
