#include "../include/zb_common.h"
#include "ss_internal.h"
#include "../aps/aps_internal.h"
#include "../zdo/zdo_internal.h"
#include "../zdo/zdo_stackUse.h"
#ifdef ZB_SECURITY
#define			DEBUG_NVKEYSAVE				0
#if ZB_COORDINATOR_ROLE
_CODE_SS_ aps_status_t ss_apsVerifyKeyCmdValid(ss_dev_pair_set_t *sd, u8 keyType){

	if(!g_zbNwkCtx.handle.is_tc){
		return APS_STATUS_ILLEGAL_REQUEST;
	}
	if(keyType != SS_TC_LINK_KEY || ss_securityModeIsDistributed()){
		return APS_STATUS_NOT_SUPPORTED;
	}

	//if no entry or the key attribute is not UNVERIFIED_KEY and VERIFED_KEY
	if(!sd || (sd->keyAttr == SS_PROVISIONAL_KEY)){
		return APS_STATUS_SECURITY_FAIL;
	}
	return APS_STATUS_SUCCESS;
}

_CODE_SS_ void ss_apsVerifyKeyReqHandle(void *p){

	aps_data_ind_t *ind = p;

	if(ZB_NWK_IS_ADDRESS_BROADCAST(ind->dst_addr)){
		zb_buf_free(p);
		return;
	}
	ss_verifyKeyFrame_t req;
	memcpy((u8 *)&req,ind->asdu,sizeof(req));
	ss_dev_pair_set_t *sd = ss_devKeyPairSearch(req.srcAddr);
	aps_status_t st = ss_apsVerifyKeyCmdValid(sd,req.stKeyType);
	if(st == APS_STATUS_SUCCESS){
		u8 padV = 3;
		u32 keyTemp[AES_BLOCK_SIZE/4];//No need set to 0, will be set in function
		ss_keyHash(&padV,sd->linkKey,(u8 *)keyTemp);
		if(memcmp((u8 *)keyTemp,req.iniVerifyKeyHashVal,AES_BLOCK_SIZE)){
			st = APS_STATUS_SECURITY_FAIL;
		}
	}

	ss_confirmKeyFrame_t *f;
	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	cmdSendReq.aduLen = sizeof(*f);
	TL_BUF_INITIAL_ALLOC((zb_buf_t *)p, cmdSendReq.aduLen, f,ss_confirmKeyFrame_t *);

	f->cmdId = APS_CMD_CONFIRM_KEY;
	f->st = st;
	f->stKeyType = req.stKeyType;
	ZB_IEEE_ADDR_COPY(f->dstAddr,req.srcAddr);

	cmdSendReq.adu = (u8 *)f;
	cmdSendReq.addrM = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
	cmdSendReq.secureNwkLayer = TRUE;
	if(st == APS_STATUS_SUCCESS){
		//TL_SCHEDULE_TASK(zdo_ssInfoSaveToFlash,NULL);
		sd->keyAttr = SS_VERIFIED_KEY;
		ss_devKeyPairSyn(SS_DEVKEYPAIR_SYNID_KEYATTR);
		cmdSendReq.secure = TRUE;
	}

	cmdSendReq.dstShortAddr = ind->src_short_addr;
	cmdSendReq.txBuf = p;
	aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_CONFIRM_KEY);
}

_CODE_SS_ static u8 ss_apsTCLKeyReqProcess(u16 dstAddr, void *buf){
	ss_dev_pair_set_t *sd= NULL;
	addrExt_t extAddr;
	u8 idx;
	if(tl_zbExtAddrByShortAddr(dstAddr, extAddr, &idx)!=NWK_STATUS_SUCCESS){
		return RET_ERROR;
	}

	sd = ss_devKeyPairSearch(extAddr);
	switch(ss_ib.tcPolicy.allowTCLKrequest){
		case	1://
		{
			if(!sd){
				sd = ss_freeDevKeyPairGet();
				if(!sd){
					return RET_ERROR;
				}

			}
			generateRandomData(sd->linkKey,CCM_KEY_SIZE);
		}
			break;
		case	2:
		{
			 if(!sd || (sd->keyAttr != SS_PROVISIONAL_KEY)){
				 return RET_ERROR;
			 }
		}
			break;
		default:
		{
			return RET_ERROR;
		}
			break;
	}

	sd->used = 1;
	ZB_IEEE_ADDR_COPY(sd->device_address,extAddr);
	sd->apsLinkKeyType = SS_UNIQUE_LINK_KEY;
	sd->incomingFrmaeCounter = 0;
	sd->outgoingFrameCounter = 0;
	sd->keyAttr = SS_UNVERIFIED_KEY;

	ss_devKeyPairSyn(SS_DEVKEYPAIR_SYNID_ALL);

	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	u8 *pAddr = NULL;
	TL_BUF_INITIAL_ALLOC((zb_buf_t *)buf, (SS_APSTXKEY_MAXPAYLOAD + 4), pAddr, u8 *);
	u8 *ptr = pAddr;
//	typedef struct{
//		u8				cmdId;
//		u8				keyType;
//		u8				key[16];
//						variable
//	}ss_apsAppLinkKey_t;

	*ptr++ = APS_CMD_TRANSPORT_KEY;//cmd ID
	*ptr++ = SS_TC_LINK_KEY;//key type
	memcpy(ptr,sd->linkKey, CCM_KEY_SIZE);
	ptr += CCM_KEY_SIZE;
	ZB_IEEE_ADDR_COPY(ptr,extAddr);
	ptr += EXT_ADDR_LEN;
	ZB_IEEE_ADDR_COPY(ptr, g_zbMacPib.extAddress);
	ptr += EXT_ADDR_LEN;

	cmdSendReq.secureNwkLayer = TRUE;
	cmdSendReq.addrM = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
	cmdSendReq.dstShortAddr = dstAddr;
	cmdSendReq.adu = pAddr;
	cmdSendReq.aduLen = ptr - pAddr;
	cmdSendReq.txBuf = buf;
	cmdSendReq.secure = TRUE;
	aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_TRANSPORT_KEY);

	return RET_OK;
}


_CODE_SS_ void ss_apsKeyReqHandle(void *p){
	aps_data_ind_t *ind = p;
	/*typedef struct{
		u8					cmdID;
		u8					keyType;
		addrExt_t			partnerExtAddr;
	}ss_apsKeyReq_frame_t;*/

	u8 *ptr = ind->asdu + 1;
	ss_keyReqType_e keyType = *ptr++;
	if(g_zbNwkCtx.handle.is_tc){
#if 0 //Doesn't support APP LK now
		//Any application link key requests that is not APS encrypted shall be dropped
		if((keyType == SS_KEYREQ_TYPE_APPLK) && (ind->security_status & SECURITY_IN_APSLAYER)){
			ss_apsAppLinkKeyReqProcess(ptr);

		}else if(keyType == SS_KEYREQ_TYPE_TCLK){

		}
#endif
		if((keyType == SS_KEYREQ_TYPE_TCLK)/*&&(ind->security_status & SECURITY_IN_APSLAYER)*/){

			if(ss_apsTCLKeyReqProcess(ind->src_short_addr,p) == RET_OK){
				return;
			}
		}
	}
	zb_buf_free(p);
}
#endif


#ifdef ZB_ROUTER_ROLE
/********************************************************************************************************
 * @brief	Internal used function for relaying SKKE CMDs directly to NWK layer to send out(doesn't use APS cmd send flow)
 *
 * @param	nwkAddr: dst network address for this packet
 * 			handle:	network layer handle, if "0", function would assign APS layer handle to network layer
 * 					if "0xfe" represents routers' relay message
 * 			nsduLen: network layer data-payload length
 * 			nsdu:	data-payload address
 * 			p:		buffer
 * 	@return	none
 */
_CODE_SS_ static void ss_relayPacketToNwk(u16 nwkAddr, u8 handle, u8 nsduLen, u8 *nsdu, void *p){
	nlde_data_req_t *nldereq = p;
	memset((u8 *)nldereq,0,sizeof(nlde_data_req_t));
	nldereq->radius = 5;
	nldereq->addrMode = APS_SHORT_DSTADDR_WITHEP;
	nldereq->discoverRoute = 1;
	nldereq->dstAddr = nwkAddr;
	nldereq->securityEnable = FALSE;
	if(handle){
		nldereq->ndsuHandle = handle;//represent relay packet
	}else{
		nldereq->ndsuHandle = (aps_get_current_counter_value() & APS_HANDLE_RANGE_MASK);
	}
	//todo need replaced, shouldn't be rely on buffer header field
	nldereq->nsduLen = nsduLen;
	nldereq->nsdu = nsdu;
	tl_zbNwkNldeDataRequest(p);
}

void ss_apsTunnelCmdHandle(void *p){
	aps_data_ind_t *ind = p;
	u8 *pAddr = ind->asdu;
	addrExt_t extAddr;
	memcpy(extAddr,(pAddr+1),8);
	u8 addrRef = 0;
	//Check dst address is one of router's child
	tl_zb_normal_neighbor_entry_t *nbe = NULL;
	u8 freeBuf = 1;
	if(tl_idxByExtAddr(&addrRef,extAddr) == NWK_STATUS_SUCCESS){
		nbe = tl_zbNeighborTableSearchFromAddrmapIdx(addrRef);
		if(nbe && ((nbe->relationship == NEIGHBOR_IS_UNAUTH_CHILD)||(nbe->relationship == NEIGHBOR_IS_CHILD))){
			u16 addr=tl_zbshortAddrByIdx(addrRef);
			ss_relayPacketToNwk(addr,APS_CMD_HANDLE_TXKEYCMD_RELAY,ind->asduLength-9,pAddr+9,p);
			nbe->relationship = NEIGHBOR_IS_CHILD;
			freeBuf = 0;
		}
	}
	if(freeBuf){
		zb_buf_free((zb_buf_t*)p);
	}

}

_CODE_SS_ static u8 ss_txKeyReqVal(u8 keyType, addrExt_t addr){
	if(ZB_IEEE_ADDR_IS_ZERO(addr) && (keyType != SS_STANDARD_NETWORK_KEY)){
		return RET_ERROR;
	}
	return RET_OK;
}


_CODE_SS_ void ss_apsmeTxKeyReq(void *p){

	ss_apsmeTxKeyReq_t *req = p;
	DEBUG(APS_LAYER_DEBUG_EN,"Receive TX KEY req, with key type %x\n",req->keyType);
	bool sTx = FALSE;
	u8 handle = APS_CMD_HANDLE_TRANSPORT_KEY;
	if(ss_txKeyReqVal(req->keyType,req->dstAddr) != RET_OK){
		return;
	}

	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	u8 *pAddr = NULL;
	TL_BUF_INITIAL_ALLOC((zb_buf_t *)p, (SS_APSTXKEY_MAXPAYLOAD + 4), pAddr, u8 *);
	u8 *ptr = pAddr;
//	typedef struct{
//		u8				cmdId;
//		u8				keyType;
//		u8				key[16];
//						variable
//	}ss_apsAppLinkKey_t;

	*ptr++ = APS_CMD_TRANSPORT_KEY;//cmd ID
	*ptr++ = req->keyType;//key type
	memcpy(ptr,req->key, CCM_KEY_SIZE);

	ptr += CCM_KEY_SIZE;
	cmdSendReq.secureNwkLayer = TRUE;
	if(ZB_IEEE_ADDR_IS_ZERO(req->dstAddr)){
		cmdSendReq.addrM = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
		cmdSendReq.dstShortAddr = NWK_BROADCAST_ALL_DEVICES;
	}else{
		cmdSendReq.addrM = ZB_ADDR_64BIT_DEV;
		if(req->relayByParent){
			SS_TUNNELCMD_SETTARGETADDR(pAddr,req->dstAddr);
			ZB_IEEE_ADDR_COPY(cmdSendReq.dstExtAddr, req->partnerAddr);
		}else{
			ZB_IEEE_ADDR_COPY(cmdSendReq.dstExtAddr, req->dstAddr);
		}
	}

	if((ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_GLOBALLINKKEY) ||
		(ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_UNIQUELLINKKEY)){
		if (!req->relayByParent){
			cmdSendReq.secureNwkLayer = FALSE;
			sTx = TRUE; //joining device has pre-configured key
		}else{
			handle = APS_CMD_HANDLE_CMD_TUNNEL;
		}
	}

	//SS_STANDARD_NETWORK_KEY
    if(req->keyType == SS_STANDARD_NETWORK_KEY){
    	/*typedef struct{
    		u8				cmdId;
    		u8				keyType;
    		u8				key[16];
    		u8				seqNum;
    		addrExt_t		destAddr;
    		addrExt_t		srcAddr;
    	}ss_apsNwkKey_t;*/
    	*ptr++ = req->keySeqNum;
    	//The source address sub-field shall be set to the local device address
    	ZB_IEEE_ADDR_COPY(ptr, req->dstAddr);
    	ptr += EXT_ADDR_LEN;

    	if(ss_securityModeIsDistributed()){
    		ZB_IEEE_ADDR_COPY(ptr, ss_ib.trust_center_address);
    	}else{
    		ZB_IEEE_ADDR_COPY(ptr, g_zbMacPib.extAddress);
    	}

    	ptr += EXT_ADDR_LEN;
    }else if(req->keyType == SS_TC_LINK_KEY){
    	/*typedef struct{

    		addrExt_t		destAddr;
    		addrExt_t		srcAddr;
    	}ss_apsTcLinkKey_t;*/
		//The source address sub-field shall be set to the local device address
		ZB_IEEE_ADDR_COPY(ptr, req->dstAddr);
		ptr += EXT_ADDR_LEN;
		ZB_IEEE_ADDR_COPY(ptr, g_zbMacPib.extAddress);
		ptr += EXT_ADDR_LEN;
    }else if(req->keyType == SS_APP_LINK_KEY){
    	/*typedef struct{


    		addrExt_t		partnerAddr;
    		u8				initiatorFlag;
    	}ss_apsAppLinkKey_t;*/
    	ZB_IEEE_ADDR_COPY(ptr, req->partnerAddr);
    	ptr += EXT_ADDR_LEN;
    	*ptr++ = req->initatorFlag;
    }

	cmdSendReq.adu = pAddr;
	cmdSendReq.aduLen = ptr - pAddr;
	cmdSendReq.txBuf = p;
	cmdSendReq.secure = sTx;
	aps_cmd_send(&cmdSendReq,handle);
}


/**Send UPDATE-DEVICE.request from ZR to TC.

   Inform TC that new devive joined network.
   TC must send nwk key to it.*/
_CODE_SS_ void ss_apsmeUpdateDevReq(void *p){
	ss_apsmeDevUpdateReq_t *req = p;
	ss_apsDevUpdate_frame_t *q = NULL;
	u8 pLen = sizeof(ss_apsDevUpdate_frame_t);
	TL_BUF_INITIAL_ALLOC((zb_buf_t *)p,pLen,q,ss_apsDevUpdate_frame_t *);
	q->cmdId = APS_CMD_UPDATE_DEVICE;
	ZB_IEEE_ADDR_COPY(q->devExtAddr, req->devAddr);

	COPY_U16TOBUFFER(&q->devShortAddr_l,req->devShortAddr);

	q->status = req->status;
	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	cmdSendReq.adu = (u8 *)q;
	cmdSendReq.aduLen = pLen;
	cmdSendReq.dstShortAddr = 0;
	cmdSendReq.addrM = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
	cmdSendReq.txBuf = p;
#if ZB_TEST_ENABLE
	extern bool apsSecurityEn;
	cmdSendReq.secure = apsSecurityEn;
	if(ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_NOKEY || ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_NWKKEY || ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_GLOBALLINKKEY)
		cmdSendReq.secureNwkLayer = TRUE;
#else
	cmdSendReq.secure = TRUE;
	cmdSendReq.secureNwkLayer = TRUE;
#endif
	aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_UPDATE_DEVICE);
}

_CODE_SS_ void ss_apsKeySwitchReq(void *p){
	ss_apsKeySwitchReq_t *req = p;
	ss_apsKeySwitch_frame_t *payLoad = NULL;
	TL_BUF_INITIAL_ALLOC((zb_buf_t *)p, sizeof(ss_apsKeySwitch_frame_t), payLoad, ss_apsKeySwitch_frame_t *);
	payLoad->apsCmdID = APS_CMD_SWITCH_KEY;
	payLoad->seqNum = req->keySeqNum;

	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	cmdSendReq.adu = (u8 *)payLoad;
	cmdSendReq.aduLen = sizeof(ss_apsKeySwitch_frame_t);
	if(ZB_EXTPANID_IS_ZERO(req->destddr)){
		cmdSendReq.dstShortAddr = 0xffff;
		cmdSendReq.addrM = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
	}else{
		cmdSendReq.addrM = ZB_ADDR_64BIT_DEV;
		ZB_IEEE_ADDR_COPY(cmdSendReq.dstShortAddr,req->destddr);
	}
	cmdSendReq.txBuf = p;
	cmdSendReq.secure = !(bool)ZB_NWK_IS_ADDRESS_BROADCAST(cmdSendReq.dstShortAddr);

	aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_SWITCH_KEY);
}

_CODE_SS_ void ss_apsDeviceUpdateCmdHandle(void *p){
	// get source address from the nwk header and convert it to long address
	aps_data_ind_t *ind = p;
	if(!(ind->security_status & SECURITY_IN_APSLAYER) && (ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_UNIQUELLINKKEY)){
		zb_buf_free((zb_buf_t*)p);
		return;
	}
	ss_apsDevUpdate_frame_t pkt;
	memcpy((u8 *)&pkt,ind->asdu,sizeof(ss_apsDevUpdate_frame_t));

	ss_apsmeDevUpdateInd_t *q = p;


	COPY_BUFFERTOU16(q->devShortAddr,&pkt.devShortAddr_l);
	ZB_IEEE_ADDR_COPY(q->devAddr, pkt.devExtAddr);
	q->status = pkt.status;
	u8 idx;
	if(tl_zbExtAddrByShortAddr(ind->src_short_addr,q->srcAddr, &idx) == TL_RETURN_INVALID){
		zb_buf_free((zb_buf_t *)p);
		return;
	}
	//generate device update indication to ZDO layer
	TL_SCHEDULE_TASK(ss_zdoUpdateDeviceIndicationHandle, p);
	//Update device record info
}

/**************************************************************************************************
 * @brief	The ZDO of a device (for example, a Trust Center) shall issue this primitive when
			it wants to request that a parent device (for example, a router) remove one of its
			children from the network. For example, a Trust Center can use this primitive to
			remove a child device that fails to authenticate properly
 * @param	ss_apsDevRemoveReq_t
 *
 * @return	none
 */

_CODE_SS_ u8 ss_apsDeviceRemoveReq(ss_apsDevRemoveReq_t *p){
	u16 parentShortAddr;
	u8 idx;

	if(tl_zbShortAddrByExtAddr(&parentShortAddr,p->parentAddr,&idx) == TL_RETURN_INVALID){
		return APS_STATUS_ILLEGAL_REQUEST;
	}

	zb_buf_t *buf = zb_buf_allocate();

	if(!buf){
		return APS_STATUS_INTERNAL_BUF_FULL;
	}

	u8 *pAddr;
	u8 pLen = sizeof(ss_apsDevRemoveFrame_t);
	TL_BUF_INITIAL_ALLOC(buf,pLen,pAddr,u8 *);
	*pAddr = APS_CMD_REMOVE_DEVICE;
	memcpy((pAddr + 1),p->targetExtAddr,8);

	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	cmdSendReq.adu = pAddr;
	cmdSendReq.aduLen = pLen;
	cmdSendReq.dstShortAddr = parentShortAddr;
	cmdSendReq.txBuf = (void *)buf;
	cmdSendReq.addrM = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
#if ZB_TEST_ENABLE
	extern bool apsSecurityEn;
	cmdSendReq.secure = apsSecurityEn;
#else
	cmdSendReq.secure = TRUE;
#endif
	cmdSendReq.secureNwkLayer = TRUE;
	aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_REMOVE_DEVICE);
	return APS_STATUS_SUCCESS;
}

_CODE_SS_ void ss_apsDeviceRemoveCmdHandle(void *p){
	aps_data_ind_t *ind = p;
	u16 srcNwkAddr = ind->src_short_addr;
	ss_apsDevRemoveInd_t *ri = p;
	//Copy child ext address
	memcpy(ri->childExtAddr,(ind->asdu+1),8);
	u8 idx;
	if(tl_zbExtAddrByShortAddr(srcNwkAddr,ri->tcAddr, &idx) == TL_RETURN_INVALID){
		zb_buf_free((zb_buf_t *)p);
		return;
	}
	/*issue this primitive to inform the ZDO that it received a
	remove-device command frame.*/
	TL_SCHEDULE_TASK(ss_zdoRemoveDeviceInd,p);
}


_CODE_SS_ static void ss_apsNwkKeyTxCmd2ED(void *p, u8 keyIndx, u16 dstShortAddr){


	bool sTx = FALSE;
	u8 handle = APS_CMD_HANDLE_TRANSPORT_KEY;

	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	u8 *pAddr = NULL;
	TL_BUF_INITIAL_ALLOC((zb_buf_t *)p, SS_APSTXKEY_MAXPAYLOAD, pAddr, u8 *);
	u8 *ptr = pAddr;
//	typedef struct{
//		u8				cmdId;
//		u8				keyType;
//		u8				key[16];
//						variable
//	}ss_apsAppLinkKey_t;

	*ptr++ = APS_CMD_TRANSPORT_KEY;//cmd ID
	*ptr++ = SS_STANDARD_NETWORK_KEY;//key type
	memcpy(ptr,ss_ib.nwkSecurMaterialSet[keyIndx].key, CCM_KEY_SIZE);
	ptr += CCM_KEY_SIZE;
	cmdSendReq.secureNwkLayer = TRUE;
	cmdSendReq.dstShortAddr = dstShortAddr;



	//SS_STANDARD_NETWORK_KEY

	/*typedef struct{
		u8				cmdId;
		u8				keyType;
		u8				key[16];
		u8				seqNum;
		addrExt_t		destAddr;
		addrExt_t		srcAddr;
	}ss_apsNwkKey_t;*/
	*ptr++ =ss_ib.nwkSecurMaterialSet[keyIndx].keySeqNum;
	//The source address sub-field shall be set to the local device address
	ZB_IEEE_ADDR_ZERO(ptr);
	ptr += EXT_ADDR_LEN;
	ZB_IEEE_ADDR_COPY(ptr, ss_ib.trust_center_address);
	ptr += EXT_ADDR_LEN;


	cmdSendReq.adu = pAddr;
	cmdSendReq.aduLen = ptr - pAddr;
	cmdSendReq.txBuf = p;
	cmdSendReq.secure = sTx;
	aps_cmd_send(&cmdSendReq,handle);
}

struct nwk2ED_t{
	u8		keySeqNum;
	u8		addrMapIndx;
}ss_nwkKey2ED;

_CODE_SS_ void ss_apsPassNwkKeyToEDcb(u16 dstAddr){
	zb_buf_t *buf = (zb_buf_t *)zb_buf_allocate();
	if(!buf){
		return;
	}
	u8 nn = tl_zbNeighborTableNumGet();
	tl_zb_normal_neighbor_entry_t *ne;
	for(u8 i= ss_nwkKey2ED.addrMapIndx;i<nn;i++){
		ne = tl_zbNeighborEntryGetFromIdx(i);
		if(tl_zbshortAddrByIdx(ne->addrmapIdx) == dstAddr){
			ss_nwkKey2ED.addrMapIndx = i+1;
			ss_apsNwkKeyTxCmd2ED(buf,ss_nwkKey2ED.keySeqNum,dstAddr);
			return;
		}
	}
	zb_buf_free(buf);
	tl_zbNwkUnreigsterPollCb();
	memset((u8 *)&ss_nwkKey2ED,0,sizeof(ss_nwkKey2ED));
}

_CODE_SS_ void ss_apsPassNwkKeyToED(u8 keyIndx){
	ss_nwkKey2ED.keySeqNum = keyIndx;
	ss_nwkKey2ED.addrMapIndx = 0;
	tl_zbNwkReigsterPollCb(ss_apsPassNwkKeyToEDcb);
}

#endif  /* ZB_ROUTER_ROLE */


_CODE_SS_ aps_status_t ss_apsmeRequestKeyReq(u8 keyType, addrExt_t dstAddr, addrExt_t partnerAddr){
	if(!ss_ib.tcPolicy.updateTCLKrequired){
		return APS_STATUS_ILLEGAL_REQUEST;
	}
	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	cmdSendReq.aduLen = (keyType == SS_KEYREQ_TYPE_APPLK)?sizeof(ss_requestKeyFrame_t):(sizeof(ss_requestKeyFrame_t) - EXT_ADDR_LEN);
	aps_status_t st = aps_txBufInit(&cmdSendReq.txBuf,&cmdSendReq.adu,cmdSendReq.aduLen);
	if( st != APS_STATUS_SUCCESS){
		return st;
	}
	u8 *ptr = cmdSendReq.adu;
	*ptr++ = APS_CMD_REQUEST_KEY;
	*ptr++ = keyType;
	if(keyType == SS_KEYREQ_TYPE_APPLK){
		ZB_IEEE_ADDR_COPY(ptr,partnerAddr);
	}
	cmdSendReq.secureNwkLayer = TRUE;
	cmdSendReq.addrM = ZB_ADDR_64BIT_DEV;
	ZB_IEEE_ADDR_COPY(cmdSendReq.dstExtAddr,ss_ib.trust_center_address);
	cmdSendReq.secure = FALSE;
	aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_REQUEST_KEY);
	return APS_STATUS_SUCCESS;
}

_CODE_SS_ void ss_apsConfirmKeyHandle(void *p){
	aps_data_ind_t *ind = p;
	/*typedef struct{
		u8					cmdId;
		u8					st;
		u8					stKeyType;//standard key type
		addrExt_t			dstAddr;
	}ss_confirmKeyFrame_t;*/
	u8 *ptr = ind->asdu + 1;
	u8 st = *ptr++;
	u8 stKeyType = *ptr++;

	ss_dev_pair_set_t *sd = ss_devKeyPairSearch(ss_ib.trust_center_address);
	if(!sd || ZB_NWK_IS_ADDRESS_BROADCAST(ind->dst_addr) || g_zbNwkCtx.handle.is_tc
			|| (st != APS_STATUS_SUCCESS) || ss_securityModeIsDistributed() ||
			!ZB_IEEE_ADDR_CMP(ptr,g_zbMacPib.extAddress) || (stKeyType != SS_TC_LINK_KEY)){

	}else{
		sd->keyAttr = SS_VERIFIED_KEY;
		sd->incomingFrmaeCounter = 0;
		ss_devKeyPairSyn(SS_DEVKEYPAIR_SYNID_KEYATTR);
		//TL_SCHEDULE_TASK(zdo_ssInfoSaveToFlash,NULL);
	}
	bdb_retrieveTcLinkKeyDone(st);
	zb_buf_free(p);
	return;
}

_CODE_SS_ void ss_apsmeVerifyKeyReq(void *p){
	ss_verifyKeyReq_t *vr = p;
	if(!ZB_IEEE_ADDR_CMP(vr->dstAddr,ss_ib.trust_center_address)||
			g_zbNwkCtx.handle.is_tc || (vr->keyType != SS_TC_LINK_KEY)){
		DEBUG(APS_LAYER_DEBUG_EN,"verify key req failed\n");
		zb_buf_free(p);
		return;
	}

	ss_verifyKeyFrame_t *req;
	aps_cmd_send_t cmdSendReq;
	TL_SETSTRUCTCONTENT(cmdSendReq,0);
	cmdSendReq.aduLen = sizeof(*req);
	TL_BUF_INITIAL_ALLOC((zb_buf_t *)p, cmdSendReq.aduLen, req, ss_verifyKeyFrame_t *);
	cmdSendReq.adu = (u8 *)req;
	cmdSendReq.addrM = ZB_ADDR_64BIT_DEV;
	cmdSendReq.secureNwkLayer = TRUE;
	ZB_IEEE_ADDR_COPY(cmdSendReq.dstExtAddr,vr->dstAddr);
	cmdSendReq.txBuf = p;
	req->cmdId = APS_CMD_VERIFY_KEY;
	req->stKeyType = SS_TC_LINK_KEY;
	/////////////////////////////////////////////////////////////////////////////////////////////////////////
	ZB_IEEE_ADDR_COPY(req->srcAddr,g_zbMacPib.extAddress);
	ss_dev_pair_set_t *fds = ss_devKeyPairSearch(cmdSendReq.dstExtAddr);
	u32 keyTemp[CCM_KEY_SIZE/4];
	u8 padV = 3;
	ss_keyHash(&padV,fds->linkKey,(u8 *)keyTemp);
	memcpy(req->iniVerifyKeyHashVal,(u8 *)keyTemp,CCM_KEY_SIZE);
	fds->keyAttr = SS_VERIFIED_KEY;
	ss_devKeyPairSyn(SS_DEVKEYPAIR_SYNID_KEYATTR);
	aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_VERIFY_KEY);
}




_CODE_SS_ static bool ss_txKeyCmdVal(ss_seKeyType_e keyType, security_with_e se){
	if(aps_ib.aps_authenticated && !(se&SECURITY_IN_APSLAYER)){
		return FALSE;
	}
	return TRUE;
}
/*************************************************************************************************************
 * @brief	Handle TxKey CMD which received from remote device
 */
_CODE_SS_ void ss_apsTxKeyCmdHandle(void *p){
	aps_data_ind_t *ind = p;
	/*Upon receipt of a secured transport-key command, the APSME shall check the key type sub-field.
	If the key type field is set to 0x03 or 0x04 (that is, application link or Trust Center link key)
	and the receiving device is operating in the joined and authorized state and the command was not
	secured using a distributed security link key or a Trust Center link key, the command shall be discarded.
	If the device is operating in the joined and authorized state it may accept a NWK broadcast
	transport key command with Key type field set to 0x01 (that is, network key) where the message
	has no APS encryption. If the key type field is set to 0x01 (that is, network key) and the command
	was not secured using a distributed security link key, Trust Center link key, the command shall be discarded.*/
	if(aps_ib.aps_authenticated && !(ind->security_status&SECURITY_IN_APSLAYER)){
		DEBUG(APS_LAYER_DEBUG_EN,"TX key cmd error as not secured in APS layer\n");
		zb_buf_free((zb_buf_t *)p);
		return;
	}
	u8 *ptr = ind->asdu;
	ptr++;
	u8 keyType = *ptr++;
	u8 *keyData = ptr;
	ptr += CCM_KEY_SIZE;
	u8 keySeq=0;
	if(keyType == SS_STANDARD_NETWORK_KEY){
		keySeq = *ptr++;
	}
	u8 *destExtAddr = ptr;
	ptr += EXT_ADDR_LEN;
	u8 *srcExtAddr = ptr;

	if((keyType == SS_STANDARD_NETWORK_KEY) || (keyType == SS_TC_LINK_KEY)){

		if(ZB_IEEE_ADDR_CMP(destExtAddr, g_zbMacPib.extAddress)||
				((keyType == SS_STANDARD_NETWORK_KEY) && ZB_IEEE_ADDR_IS_ZERO(destExtAddr))){


			//issue APSME-TRANSPORT-KEY.indication primitive to ZDO layer
			ss_apsme_txKeyInd_t *ind = p;
			ind->keyType = keyType;
			ZB_IEEE_ADDR_COPY(ind->srcAddr,srcExtAddr);
			if(keyType == SS_STANDARD_NETWORK_KEY){
				ind->keySeqNum = keySeq;
			}
			memcpy(ind->key, keyData, CCM_KEY_SIZE);
			TL_SCHEDULE_TASK(ss_zdoApsmeTxKeyIndCb, p);
			return;
		}
#ifdef ZB_ROUTER_ROLE
		else{
			u8 addrRef;

			//Search for child in the Neighbor table, mark child as Authenticated,
			//send key to it using unsecured NWK transfer
			if(tl_idxByExtAddr(&addrRef,destExtAddr) == NWK_STATUS_SUCCESS){
				tl_zb_normal_neighbor_entry_t *nbe = tl_zbNeighborTableSearchFromAddrmapIdx(addrRef);
				if(nbe && ((nbe->relationship == NEIGHBOR_IS_UNAUTH_CHILD)||(nbe->relationship == NEIGHBOR_IS_CHILD))){
					u16 addr=tl_zbshortAddrByIdx(addrRef);
					aps_cmd_send_t cmdSendReq;
					TL_SETSTRUCTCONTENT(cmdSendReq,0);
					cmdSendReq.adu = ind->asdu;
					cmdSendReq.aduLen = ind->asduLength;
					cmdSendReq.dstShortAddr = addr;
					cmdSendReq.addrM = ZB_ADDR_16BIT_DEV_OR_BROADCAST;
					cmdSendReq.txBuf = p;
//					cmdSendReq.secure = 0;
//					cmdSendReq.ackReq = 0;
//					cmdSendReq.secureNwkLayer = 0;
					aps_cmd_send(&cmdSendReq,APS_CMD_HANDLE_TXKEYCMD_RELAY);
					nbe->relationship = NEIGHBOR_IS_CHILD;
					return;
				}
			}
		}
#endif
	}
	zb_buf_free((zb_buf_t *)p);
}

_CODE_SS_ ss_dev_pair_set_t *ss_freeDevKeyPairGet(void ){
#ifdef ZB_COORDINATOR_ROLE
	if(ss_ib.keyPairSetUsed < SECUR_N_DEVICE_PAIRSET){

		memset((u8 *)&ss_ib.ssDevKeyPairTem,0,sizeof(ss_ib.ssDevKeyPairTem));
		ss_ib.ssDevKeyPairTem.rsv = ss_ib.keyPairSetUsed++;
		DEBUG(DEBUG_NVKEYSAVE,"Free device pair get success current used num %d\n",ss_ib.keyPairSetUsed);
		return &ss_ib.ssDevKeyPairTem;
	}else{
		return NULL;
	}
#else
	for(u8 i=0; i<SECUR_N_DEVICE_PAIRSET; i++){
		if(!ss_ib.ssDeviceKeyPairSet[i].used){
			return &ss_ib.ssDeviceKeyPairSet[i];
		}
	}
	return NULL;
#endif
}



#ifdef ZB_COORDINATOR_ROLE
_CODE_SS_ u8 ss_convertKeyAttr(u8 value, bool nvToReal){
	if(nvToReal){
		if(!(value & KEYTYPE_VERIFIED_MASK)){
			return SS_VERIFIED_KEY;
		}else if(!(value & KEYTYPE_UNVERIFY_MASK)){
			return SS_UNVERIFIED_KEY;
		}else{
			return SS_PROVISIONAL_KEY;
		}
	}else{
		if(value ==SS_VERIFIED_KEY){
			return (~KEYTYPE_VERIFIED_MASK);
		}else if(value ==SS_UNVERIFIED_KEY ){
			return (~KEYTYPE_UNVERIFY_MASK);
		}else{
			return (~SS_PROVISIONAL_KEY);
		}
	}
}

_CODE_SS_ bool ss_loadDevKeyFromNv(u32 addr,ss_devPairNV_t *buf){
	flash_read_page(addr,sizeof(*buf),(u8 *)buf);
	if(!buf->itemAvailable){
		buf->keyAttr = ss_convertKeyAttr(buf->keyAttr,TRUE);
		DEBUG(DEBUG_NVKEYSAVE,"Load device key pair from NV with key type %x\n",buf->keyAttr);
		DEBUG(DEBUG_NVKEYSAVE,"Device key pair search, dst EXT ADDR ");
		printfArray(buf->device_address,8);
		return TRUE;
	}
	return FALSE;
}

_CODE_SS_ u32 ss_devKeySpaceGet(u8 usedNum){
	u32 addr = 0;
	for(u8 i= usedNum; i<SS_DEVKEYPAIRMAXNUM_PERPAGE;i++){
		 addr = i*SS_DEVKEYPAIRNV_SPACE + MOUDLES_START_ADDR(NV_MODULE_KEYPAIR);
		 u8 itemAva = 0;
		 flash_read_page(addr,1,&itemAva);
		 if(itemAva == 0xff){
			 return addr;
		 }
	}
	//If goes here, the 4k page is full, need sort the page
	//Move key device pair set to the cache NV
	u32 addrCache = MOUDLES_START_ADDR(NV_MODULE_CACHE);
	u32 addrData = MOUDLES_START_ADDR(NV_MODULE_KEYPAIR);
	flash_erase_sector(addrCache);
	for(u8 i=0; i<usedNum;i++){
		ss_devPairNV_t dpNV;
		flash_read_page(ss_ib.ssDeviceKeyPairSet[i].nvAddr,sizeof(dpNV),(u8 *)&dpNV);
		flash_write_page(addrCache + i*SS_DEVKEYPAIRNV_SPACE,sizeof(dpNV),(u8 *)&dpNV);
		ss_ib.ssDeviceKeyPairSet[i].nvAddr = addrData + i*SS_DEVKEYPAIRNV_SPACE;
	}
	flash_erase_sector(addrData);
	for(u8 i=0; i<usedNum;i++){
		ss_devPairNV_t dpNV;
		flash_read_page(addrCache + i*SS_DEVKEYPAIRNV_SPACE,sizeof(dpNV),(u8 *)&dpNV);
		flash_write_page(addrData + i*SS_DEVKEYPAIRNV_SPACE,sizeof(dpNV),(u8 *)&dpNV);
	}
	return (addrData + usedNum*SS_DEVKEYPAIRNV_SPACE);
}


#endif


_CODE_SS_ void ss_devKeyPairSyn(ss_devKeyPairSyn_id synID){
#ifdef ZB_COORDINATOR_ROLE
	if(synID == SS_DEVKEYPAIR_SYNID_KEYATTR){
		u8 keyType = ss_convertKeyAttr(ss_ib.ssDevKeyPairTem.keyAttr,FALSE);

		u32 addr = ss_ib.ssDeviceKeyPairSet[ss_ib.ssDevKeyPairTem.rsv].nvAddr + OFFSETOF(ss_devPairNV_t,keyAttr);
		DEBUG(DEBUG_NVKEYSAVE,"Keytype changed to %x, write to flash addr %x\n",keyType,addr);
		flash_write_page(addr,1,&keyType);
	}else if(synID == SS_DEVKEYPAIR_SYNID_INCOMMINGFRAMECNT){
		ss_ib.ssDeviceKeyPairSet[ss_ib.ssDevKeyPairTem.rsv].incomingFrmaeCounter = ss_ib.ssDevKeyPairTem.incomingFrmaeCounter;
	}else{
		ss_devPairNV_t dpNV;
		ss_ib.ssDeviceKeyPairSet[ss_ib.ssDevKeyPairTem.rsv].nvAddr = ss_devKeySpaceGet(ss_ib.keyPairSetUsed);
		DEBUG(DEBUG_NVKEYSAVE,"Get new NV address for key store %x\n",ss_ib.ssDeviceKeyPairSet[ss_ib.ssDevKeyPairTem.rsv].nvAddr);
		ss_ib.ssDeviceKeyPairSet[ss_ib.ssDevKeyPairTem.rsv].incomingFrmaeCounter = 0;
		dpNV.itemAvailable = 0;

		memcpy(dpNV.device_address,ss_ib.ssDevKeyPairTem.device_address,NV_ITEM_COPYLEN);
		dpNV.keyAttr = ss_convertKeyAttr(ss_ib.ssDevKeyPairTem.keyAttr,FALSE);
		flash_write_page(ss_ib.ssDeviceKeyPairSet[ss_ib.ssDevKeyPairTem.rsv].nvAddr,sizeof(dpNV),(u8 *)&dpNV);
	}
#endif
}
_CODE_SS_ ss_dev_pair_set_t *ss_devKeyPairGet(addrExt_t extAddr){
#ifdef ZB_COORDINATOR_ROLE
	DEBUG(DEBUG_NVKEYSAVE,"Device key pair get, src EXT ADDR ");
	printfArray(extAddr,8);
	for(u8 i=0; i<ss_ib.keyPairSetUsed;i++){
		ss_devPairNV_t dpNV;
		if(ss_loadDevKeyFromNv(ss_ib.ssDeviceKeyPairSet[i].nvAddr,&dpNV) && (dpNV.keyAttr != SS_UNVERIFIED_KEY)
				&& ZB_IEEE_ADDR_CMP(extAddr,dpNV.device_address)){
			DEBUG(DEBUG_NVKEYSAVE,"Device key pair get success, index %d\n",i);
			ss_ib.ssDevKeyPairTem.rsv = i;
			ss_ib.ssDevKeyPairTem.incomingFrmaeCounter = ss_ib.ssDeviceKeyPairSet[i].incomingFrmaeCounter;
			memcpy(ss_ib.ssDevKeyPairTem.device_address,dpNV.device_address,NV_ITEM_COPYLEN);
			return &ss_ib.ssDevKeyPairTem;
		}
	}
	return NULL;
#else
	for(u8 i=0; i<SECUR_N_DEVICE_PAIRSET;i++){
		if((ss_ib.ssDeviceKeyPairSet[i].keyAttr != SS_UNVERIFIED_KEY) && ZB_IEEE_ADDR_CMP(extAddr,ss_ib.ssDeviceKeyPairSet[i].device_address)){
			return &ss_ib.ssDeviceKeyPairSet[i];
		}
	}
	return NULL;
#endif
}


_CODE_SS_ ss_dev_pair_set_t *ss_devKeyPairSearch(addrExt_t extAddr){
#ifdef ZB_COORDINATOR_ROLE
	for(u8 i=0; i<ss_ib.keyPairSetUsed;i++){
		ss_devPairNV_t dpNV;
		if(ss_loadDevKeyFromNv(ss_ib.ssDeviceKeyPairSet[i].nvAddr,&dpNV)
				&& ZB_IEEE_ADDR_CMP(extAddr,dpNV.device_address)){
			DEBUG(DEBUG_NVKEYSAVE,"Device key pair search success, index %d\n",i);
			ss_ib.ssDevKeyPairTem.rsv = i;
			ss_ib.ssDevKeyPairTem.incomingFrmaeCounter = ss_ib.ssDeviceKeyPairSet[i].incomingFrmaeCounter;
			memcpy(ss_ib.ssDevKeyPairTem.device_address,dpNV.device_address,NV_ITEM_COPYLEN);
			return &ss_ib.ssDevKeyPairTem;
		}
	}
	return NULL;
#else
	for(u8 i=0; i<SECUR_N_DEVICE_PAIRSET;i++){
		if(ZB_IEEE_ADDR_CMP(extAddr,ss_ib.ssDeviceKeyPairSet[i].device_address)){
			return &ss_ib.ssDeviceKeyPairSet[i];
		}
	}
	return ((ss_dev_pair_set_t *)NULL);
#endif
}
/*************************************************************************************************************
 * @brief	Handle The APSME-SWITCH-KEY.request primitive which is used to allow a device (for example, the Trust Center)
			to inform another device that it should switch to a new active network key.
 */
_CODE_SS_ void ss_apsSwitchKeyCmdHandle(u8 keySeqNum){
	ss_zdoNwkKeySwitch(keySeqNum);
}

#endif
