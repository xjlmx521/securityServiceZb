
#include "../include/zb_common.h"
#include "ss_internal.h"
//#include "../aps/aps_data.h"
#include "../zdo/zdo_stackUse.h"
#ifdef ZB_SECURITY
tl_zb_normal_neighbor_entry_t *g_nbEntyBackup = NULL;

_CODE_SS_ static void ss_nwkSecureStatus(void *arg, u16 addrShort, u8 status){
	nlme_nwkStatus_ind_t *cmd = (nlme_nwkStatus_ind_t *)arg;
	cmd->status = (nwk_statusCode_t)status;
	cmd->nwkAddr = addrShort;
	DEBUG(DEBUG_ENDECRYPT,"NWK secure status deliver %x\n",status);
	TL_SCHEDULE_TASK(zdo_nlme_status_indication_cb, arg);
}


_CODE_SS_ u8 ss_nwkSecureFrame(zb_buf_t *src, u8 nwkHdrAuxLen){

	u8 ret = 0;

	zb_mscp_data_req_t *req = (zb_mscp_data_req_t *)src;

	ss_apsNwkAuxFrameHdr_t aux;
	memset((u8 *)&aux,0,sizeof(aux));
	u8 auxLen = sizeof(ss_apsNwkAuxFrameHdr_t);
	u8 nwkHdrLen = nwkHdrAuxLen - auxLen;

   //fill aux header - see 4.5.1
	aux.keyIdentifer = SS_SECUR_NWK_KEY;//NWK key
	aux.extendedNonce = 1;//with nonce

	aux.frameCnt = ss_ib.outgoingFrameCounter++;
	aux.keySeqNum = ss_ib.activeKeySeqNum;

	ZB_IEEE_ADDR_COPY(aux.srcAddr, g_zbMacPib.extAddress);
	aux.securityLevel = 5;//security level set to 5 for encryption
	//copy AUX info the TX buffer
	memcpy(req->msdu+nwkHdrLen,(u8 *)&aux,auxLen);

    u8 *key = ss_zdoGetNwkKeyBySeqNum(aux.keySeqNum);
	if (!key) {
		ret = RET_ERROR;
	}else{
		ss_securityCcmNonce_t nonce;
		nonce.frameCnt = aux.frameCnt;
		nonce.secureCtrl = *((u8 *)(&aux));
		memcpy(nonce.srcAddr,aux.srcAddr,8);

		u8 *srcMsg = req->msdu + nwkHdrAuxLen;
		u8 srcMsgLen = req->msduLength- nwkHdrAuxLen;
		u8 *nwkHdr = req->msdu;//as NWK frame is integrity protected
		u8 len = ss_ccmEncryption(key,(u8 *)&nonce,nwkHdrAuxLen,nwkHdr,srcMsgLen,srcMsg);

		u8 *payloadAddr = NULL;

		//The update used for MAC layer transmission usage,
		req->msduLength = nwkHdrAuxLen + len;
		SS_CLR_SECURITY_LEVEL(req->msdu+nwkHdrLen);

#ifdef ZB_COORDINATOR_ROLE
		//If counter is near limit, switch key
		if (g_zbNwkCtx.handle.is_tc && (ss_ib.outgoingFrameCounter == SS_SECUR_NWK_COUNTER_LIMIT)){
			//zb_buf_allocate_delayed(zb_secur_switch_nwk_key_br);
		}
#endif
	}
	return ret;
}

_CODE_SS_ u8 ss_nwkDecryptFrame(void *p, u8 nwkHdrSize, u8 payloadSize, u8 *payloadAddr, nwk_hdr_t *nwkHdr, u8 lqi){

	zb_buf_t *nsdu = p;


	tl_zb_normal_neighbor_entry_t *nbe = NULL;
	u8 *key;
	u8 addrRef = 0;
	u8 ret = 0;
	ss_apsNwkAuxFrameHdr_t aux;

	u8 auxLen = sizeof(ss_apsNwkAuxFrameHdr_t);
	nwkHdrSize -= sizeof(aux);
	SS_SET_SECURITY_LEVEL(payloadAddr + nwkHdrSize,5);
	memcpy((u8 *)&aux,payloadAddr + nwkHdrSize,auxLen);//copy aux field

	payloadSize -= nwkHdrSize;
	payloadSize -= auxLen;

	zb_mscp_data_ind_t *pInd = p;
	u16 neighborAddr = pInd->srcAddr.addr.shortAddr;
	u8 validationNewNeighbor = 0;//To validation the new added neighbor item

    if (!nwkHdr->frameControl.multicastFlg){
    	//todo no need create item if not find item
    	ret = tl_zbNwkAddrMapAdd(neighborAddr,aux.srcAddr,&addrRef);
    }else{
		ret = tl_idxByShortAddr(&addrRef,neighborAddr);
	}

    if(ret == RET_OK){
		/* Get neighbor table entry.
		It is possible to have no dev in the neighbor.
		Create entry in the neighbor only if this is direct transmit.
		*/
    	nbe = tl_zbNeighborTableSearchFromAddrmapIdx(addrRef);
    	DEBUG(DEBUG_ENDECRYPT,"Decrypt NWK, neighbor got %x\n",nbe);
		if(nbe && (nbe->relationship != NEIGHBOR_IS_CHILD) && (nbe->relationship != NEIGHBOR_IS_UNAUTH_CHILD)){
			nbe->rxOnWhileIdle = 1;

			if(nbe->relationship == NEIGHBOR_IS_NONE_OF_ABOVE) {
				nbe->relationship = NEIGHBOR_IS_SIBLING;
			}
		}else if(!nbe){//should create an item in the neighbor table, and marked as invalid device, if decrypt success mark as valid
			g_nbEntyBackup = zb_buf_allocate();
			if(g_nbEntyBackup){
				memset(g_nbEntyBackup, 0, sizeof(tl_zb_normal_neighbor_entry_t));
				g_nbEntyBackup->addrmapIdx = addrRef;
				g_nbEntyBackup->deviceType = NWK_DEVICE_TYPE_ROUTER;
				g_nbEntyBackup->relationship = NEIGHBOR_IS_SIBLING;	//Doesn't matter for ED, as the true relationship would be update in join accept
				g_nbEntyBackup->rxOnWhileIdle = 1;
				g_nbEntyBackup->lqi = lqi;
				g_nbEntyBackup->outgoingCost = NWK_STATIC_PATH_COST;
				nbe = tl_zbNeighborTableUpdate(g_nbEntyBackup, 0);
				if(nbe){
					zb_buf_free(g_nbEntyBackup);
					g_nbEntyBackup = NULL;
				}
				validationNewNeighbor = 1;//Trigger validation procedure, if decrypt failed, should delete the item
				DEBUG(DEBUG_ENDECRYPT,"Add neighbor table %x\n",nbe);
			}
			//ret = RET_ERROR;
		}
    }


    tl_zb_normal_neighbor_entry_t *curNbe = (nbe) ? nbe : g_nbEntyBackup;
    if(ret == RET_OK && (g_nbEntyBackup || nbe)){
		if((aux.keySeqNum == 0)) {
			aux.keySeqNum = ss_ib.activeKeySeqNum;
		}
		key = ss_zdoGetNwkKeyBySeqNum(aux.keySeqNum);
		//If this is child, set its state to 'not authenticated'
		if(curNbe->relationship == NEIGHBOR_IS_CHILD){
			curNbe->relationship = NEIGHBOR_IS_UNAUTH_CHILD;
		}

		if(curNbe->keySeqNum != aux.keySeqNum){
			curNbe->incomingFrameCnt = 0;
			curNbe->keySeqNum = aux.keySeqNum;
		}
		if(!key){
			//set 'frame security failed'
			ret = RET_ERROR;
			ss_nwkSecureStatus(nsdu,neighborAddr, NWK_COMMAND_STATUS_BAD_KEY_SEQUENCE_NUMBER);
		}else{
			if ((nbe->incomingFrameCnt > aux.frameCnt) || (nbe->incomingFrameCnt == ((u32)~0))){
				ret = RET_ERROR;
				ss_nwkSecureStatus(nsdu, neighborAddr, NWK_COMMAND_STATUS_BAD_FRAME_COUNTER);
			}else{
				curNbe->incomingFrameCnt = aux.frameCnt;
			}
		}
    }else{
    	ss_nwkSecureStatus(nsdu, neighborAddr, NWK_COMMAND_STATUS_BAD_KEY_SEQUENCE_NUMBER);
    	ret = RET_ERROR;
    }//end if(ret == RET_OK)
    if(ret == RET_OK){

    	if(payloadSize < ZB_CCM_M){
			ret = RET_ERROR;
			ss_nwkSecureStatus(nsdu, neighborAddr, NWK_COMMAND_STATUS_BAD_KEY_SEQUENCE_NUMBER);
    	}
    	if(ret == RET_OK){
    		//start decrypt
    		ss_securityCcmNonce_t nonce;

			ZB_IEEE_ADDR_COPY(nonce.srcAddr, aux.srcAddr);

			nonce.frameCnt = aux.frameCnt;
			//aux.securityLevel = 5;
			nonce.secureCtrl = *((u8 *)(&aux));
			ret = ss_ccmDecryption(key,(u8 *)&nonce,nwkHdrSize+auxLen,payloadAddr,payloadSize,payloadAddr+auxLen+nwkHdrSize);
    	}
    	if (ret == RET_OK){

			//if this is child and authentication ok, set its state to 'authenticated'
			if (curNbe->relationship == NEIGHBOR_IS_UNAUTH_CHILD){
				curNbe->relationship = NEIGHBOR_IS_CHILD;
			}
    	}else{
    		if(validationNewNeighbor && nbe){
    			if(nbe){
    				tl_zbNeighborTableDelete(nbe);
    			}else if(g_nbEntyBackup){
    				zb_buf_free(g_nbEntyBackup);
    				g_nbEntyBackup = NULL;
    			}
    		}
    		ss_nwkSecureStatus(nsdu,neighborAddr, NWK_COMMAND_STATUS_BAD_KEY_SEQUENCE_NUMBER);
    	}
    }else{
    	if(g_nbEntyBackup){
			zb_buf_free(g_nbEntyBackup);
			g_nbEntyBackup = NULL;
		}
    }
    if(ret == RET_OK && (aux.keySeqNum != ss_ib.activeKeySeqNum) &&((u8)(aux.keySeqNum - ss_ib.activeKeySeqNum) < (u8)127)){

		/*Implicit key switch: according to 4.3.1.2 Security Processing of Incoming
		Frames. "If the sequence number of the received frame belongs to a newer entry in the
		nwkSecurityMaterialSet, set the nwkActiveKeySeqNumber to the received
		sequence number".*/
    	ss_zdoNwkKeySwitch(aux.keySeqNum);
    }
    DEBUG(DEBUG_ENDECRYPT,"Packet secure status %d\n",ret);
  return ret;
}
#endif
