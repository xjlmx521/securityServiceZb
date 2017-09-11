
#include "../include/zb_common.h"
#include "ss_internal.h"
#include "../aps/aps_internal.h"
#include "../nwk/includes/nwk.h"
#ifdef ZB_SECURITY
ss_info_base_t ss_ib;
#ifdef APS_FRAME_SECURITY
extern void zdo_nlme_status_indication_cb(void *param);
_CODE_SS_ static void ss_apsSecureStatus(void *arg, u16 addrShort, aps_status_t status){
	nlme_nwkStatus_ind_t *cmd = (nlme_nwkStatus_ind_t *)arg;
	cmd->status = (nwk_statusCode_t)status;
	cmd->nwkAddr = addrShort;
	DEBUG(DEBUG_ENDECRYPT,"NWK secure status deliver %x\n",status);
	TL_SCHEDULE_TASK(zdo_nlme_status_indication_cb, arg);
}

/******************************************************************************************************
 * @brief	Implement security processing of CMD and data frames
 */
_CODE_SS_ u8 ss_apsEnAuxHdrFill(void *p, ss_apsNwkKey_t *q, aps_tx_options txopt){
	ss_apsNwkAuxFrameHdr_t *aux = p;
	u8 *ptrPrivate = (((u8 *)&aux->frameCnt) + 4);
	aux->frameCnt=ss_ib.outgoingFrameCounter++;//common part
	aux->securityLevel = 5;//security level, sescurity level should be cleared to 0 after encryption
	if(q){
		aux->extendedNonce = 1;
		ZB_IEEE_ADDR_COPY(ptrPrivate,g_zbMacPib.extAddress);
		ptrPrivate += EXT_ADDR_LEN;
		if(q->cmdId == APS_CMD_TRANSPORT_KEY){
			if(q->keyType == SS_STANDARD_NETWORK_KEY){
				aux->keyIdentifer = SS_SECUR_KEY_TRANSPORT_KEY;//key load key
			}else{
				aux->keyIdentifer = SS_SECUR_KEY_LOAD_KEY;//key transport key
			}
		}else{
			aux->keyIdentifer = SS_SECUR_DATA_KEY;//Aps data key
		}
	}else{//data HDR
		if(txopt & APS_TX_OPT_INCLUDE_NONCE){
			aux->extendedNonce = 1;
			ZB_IEEE_ADDR_COPY(ptrPrivate,g_zbMacPib.extAddress);
			ptrPrivate += EXT_ADDR_LEN;
		}
		aux->keyIdentifer = SS_SECUR_DATA_KEY;//Aps data key
		if(txopt & APS_TX_OPT_USE_NWK_KEY){
			aux->keyIdentifer = SS_SECUR_NWK_KEY;
			*ptrPrivate++ = ss_ib.activeKeySeqNum;
		}

	}
	return (ptrPrivate - ((u8 *)p));
}


_CODE_SS_ u8 ss_apsSecureFrame(void *p, u8 apsHdrAuxLen,u8 apsHdrLen, addrExt_t extAddr){
	nlde_data_req_t *nldereq = p;

	ss_apsNwkAuxFrameHdr_t aux;
	memset((u8 *)&aux,0,sizeof(aux));

	u8 *payloadAddr = NULL;
	u8 *key = NULL;
	u8 keyTemp[16];
	TL_SETSTRUCTCONTENT(keyTemp,0);
	u8 *msgStartAddr = nldereq->nsdu;
	payloadAddr = msgStartAddr + apsHdrAuxLen;

	APS_SECURITY_SET((*msgStartAddr),APS_SECURITY_TYPE_TWO);

	memcpy((u8 *)&aux,msgStartAddr +apsHdrLen,apsHdrAuxLen - apsHdrLen);

	if(aux.keyIdentifer == SS_SECUR_NWK_KEY){
		/*If specifies that the active network key is required to secure the data frame,
		then security material shall be obtained by using the
		nwkActiveKeySeqNumber from the NIB to retrieve the active network key,
		outgoing frame counter, and sequence number from the
		nwkSecurityMaterialSet attribute in the NIB.*/
		key = ss_ib.nwkSecurMaterialSet[ss_ib.activeSecureMaterialIndex].key;
	}else{
		ss_dev_pair_set_t *dk = ss_devKeyPairGet(extAddr);
		if(!dk && (ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_UNIQUELLINKKEY)){
			ss_apsSecureStatus(p,nldereq->dstAddr,APS_STATUS_SECURITY_FAIL);
			return RET_ERROR;
		}

		if(dk){
			key = dk->linkKey;
		}else{
			key = ss_securityModeIsDistributed() ? tcLinkKeyDistributedSe : tcLinkKeyCentralSe;
		}
		if(aux.keyIdentifer != SS_SECUR_DATA_KEY){
			u8 padV = 0;
			if(aux.keyIdentifer ==  SS_SECUR_KEY_LOAD_KEY){
				padV = 2;
			}
			if(!ss_keyHash(&padV, key,keyTemp)){
				key = keyTemp;
			}
		}
	}
	ss_securityCcmNonce_t nonce;
	memset((u8 *)&nonce,0,sizeof(nonce));

	nonce.frameCnt = aux.frameCnt;
	aux.securityLevel = 5;//clear security level
	nonce.secureCtrl = *((u8 *)(&aux));
	ZB_IEEE_ADDR_COPY(nonce.srcAddr,g_zbMacPib.extAddress);
	u8 srcMsgLen = nldereq->nsduLen - apsHdrAuxLen;

	u8 len = ss_ccmEncryption(key,(u8 *)&nonce,apsHdrAuxLen,msgStartAddr,srcMsgLen,payloadAddr);
	nldereq->nsduLen = apsHdrAuxLen + len;//Add MIC length
	SS_CLR_SECURITY_LEVEL((msgStartAddr +apsHdrLen));
	return	0;
}

#define		SS_AUX_NONCE_INCLUDE(d)				(d&BIT(5))
_CODE_SS_ u8 ss_apsDecryptFrame(void *p){
	ss_securityCcmNonce_t nonce;
	u8 ret = RET_OK;
	u8 *key = NULL;
	u8 keyTemp[16];
	aps_header_t *apsHdr = (aps_header_t *)(NWK_DATA_INDICATION_PRIMITIVE_LEN + ((u8 *)p));
	nlde_data_ind_t *nPtr = p;
	//APS HDR
	u8 *auxStartAddr = nPtr->nsdu + apsHdr->aps_hdr_len;
	u8 *ptr = auxStartAddr;
	ss_apsEncryAuxCommonHdr_t aux;
	memcpy((u8 *)&aux,auxStartAddr,sizeof(aux));
	ptr += sizeof(aux);
	u8 auxNoncePresented = SS_AUX_NONCE_INCLUDE(*auxStartAddr);
	//Do filter below, doesn't support use NWK key to secure APS data
	if((aux.frameCnt == U32_MAX) || (aux.keyIdentifer == SS_SECUR_NWK_KEY)){
		return RET_ERROR;
	}

	u8 addrRef;
	if((tl_zbExtAddrByShortAddr(apsHdr->src_addr,nonce.srcAddr,&addrRef) == TL_RETURN_INVALID) && aps_ib.aps_authenticated){
		DEBUG(APS_LAYER_DEBUG_EN,"Decrypt error as no item in address map table of source\n");
		return RET_ERROR;
	}

	if(auxNoncePresented){
		//If joined and unauthorized, use the apsDeviceKeyPairSet that corresponds to its pre-installed link key
		ZB_IEEE_ADDR_COPY(nonce.srcAddr,ptr);
		ptr += EXT_ADDR_LEN;
	}

	ss_dev_pair_set_t *dk = ss_devKeyPairGet(nonce.srcAddr);
	if(!dk && (ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_UNIQUELLINKKEY)){
		return RET_ERROR;
	}
	if(dk){
		key = dk->linkKey;
	}else{
		key = ss_securityModeIsDistributed() ? tcLinkKeyDistributedSe : tcLinkKeyCentralSe;
	}
	//End filter

	u8 payloadLen = nPtr->nsduLen + nPtr->nsdu - ptr;
	SS_SET_SECURITY_LEVEL(auxStartAddr,5);
	if(dk && (dk->apsLinkKeyType == SS_UNIQUE_LINK_KEY)){
		/*If the apsLinkKeyType of the associated link key is 0x00 (unique) and there38 is
		an incoming frame count FrameCount corresponding to SourceAddress from
		the security material obtained in step 3 and if ReceivedFrameCount is less than
		FrameCount, security processing shall fail and no further security processing
		shall be done on this frame*/
		if(dk->incomingFrmaeCounter > aux.frameCnt){
			return RET_ERROR;
		}else{
			/*Set FrameCount to (ReceivedFrameCount + 1) and store both FrameCount and
			SourceAddress in the appropriate security material.*/
			dk->incomingFrmaeCounter = aux.frameCnt + 1;
			ss_devKeyPairSyn(SS_DEVKEYPAIR_SYNID_INCOMMINGFRAMECNT);
		}
	}
	if(aux.keyIdentifer != SS_SECUR_DATA_KEY){
		u8 padV = 0;
		if(aux.keyIdentifer ==  SS_SECUR_KEY_LOAD_KEY){
			padV = 2;
		}
		ss_keyHash(&padV,key,keyTemp);
		key = keyTemp;
	}
	nonce.frameCnt = aux.frameCnt;
	aux.securityLevel = 5;
	nonce.secureCtrl = *((u8 *)(&aux));
	ret = ss_ccmDecryption(key,(u8 *)&nonce,ptr - nPtr->nsdu,auxStartAddr - apsHdr->aps_hdr_len,payloadLen,ptr);
	//update packet info here, no encryption message in the buffer now
	if(ret == RET_OK){
		nPtr->nsduLen -=(ptr - auxStartAddr + 4);
		nPtr->nsdu += (ptr - auxStartAddr);
	}
	return ret;
}
#endif
#endif
