#include "../include/zb_common.h"
#include "../aps/aps_stackUse.h"
#include "../zdo/zdo_internal.h"
#include "../zdo/zdo_stackUse.h"
#include "ss_internal.h"
#ifdef ZB_SECURITY
static u16 ss_zdoGetUpdateDeviceStatus(u8 rj, u8 sr);

/**************************************************************************************************
 * @brief	Interface used to check whether TC allowed new device joined to its network
 */
_CODE_SS_ bool ss_zdoAcceptNewDevAllow(){
	return zdo_af_check_flag(ZDO_AF_FLAG_AUTH_ALLOW);
}


_CODE_SS_ bool ss_securityModeIsDistributed(){
	return ZB_IEEE_ADDR_IS_INVAILD(ss_ib.trust_center_address);
}

_CODE_SS_ void ss_zdoApsmeTxKeyIndCb(void *p){
	ss_apsme_txKeyInd_t *ind = p;
	u8 i = 0;
	u8 need_free_buf = 1;
	if(ind->keyType == SS_STANDARD_NETWORK_KEY){
		if(ZB_IEEE_ADDR_IS_ZERO(ss_ib.trust_center_address)){
			ZB_IEEE_ADDR_COPY(ss_ib.trust_center_address, ind->srcAddr);
		}

		if((ss_ib.preConfiguredKeyType != SS_PRECONFIGURED_NWKKEY) || (aps_ib.aps_authenticated)){//switch key CMD
			i = (ss_ib.activeSecureMaterialIndex + ind->keySeqNum - ss_ib.activeKeySeqNum)%SECUR_N_SECUR_MATERIAL;
			memcpy(ss_ib.nwkSecurMaterialSet[i].key,ind->key,CCM_KEY_SIZE);
			ss_ib.nwkSecurMaterialSet[i].keySeqNum = ind->keySeqNum;
			ss_ib.nwkSecurMaterialSet[i].keyType = ind->keyType;
			if((i == ss_ib.activeSecureMaterialIndex) && (ind->keySeqNum != ss_ib.activeKeySeqNum)){
				ss_ib.activeKeySeqNum = ind->keySeqNum;
				ss_ib.outgoingFrameCounter = 0;
			}
#ifdef	ZB_ROUTER_ROLE
			if(aps_ib.aps_authenticated)
				ss_apsPassNwkKeyToED(i);
#endif
		}

		if(!aps_ib.aps_authenticated) {
			tl_nwkBuildJoinCnfPrimitive(p,MAC_SUCCESS);
			aps_ib.aps_authenticated = 1;
			ss_ib.activeKeySeqNum = ind->keySeqNum;
			ss_ib.outgoingFrameCounter = 0;
			ss_ib.activeSecureMaterialIndex = i;

			if(g_zdo_nwk_manager.authCheckTimer){
				TL_ZB_TIMER_CANCEL(&g_zdo_nwk_manager.authCheckTimer);
			}

			TL_SCHEDULE_TASK(zdo_nlme_join_confirm,p);
			need_free_buf = 0;

      }
	}else if(ind->keyType == SS_TC_LINK_KEY){
		ss_dev_pair_set_t *sd = &ss_ib.ssDeviceKeyPairSet[0];
		sd->used = 1;
		ZB_IEEE_ADDR_COPY(sd->device_address,ind->srcAddr);
		sd->apsLinkKeyType = SS_UNIQUE_LINK_KEY;
		sd->incomingFrmaeCounter = 0;
		sd->outgoingFrameCounter = 0;
		sd->keyAttr = SS_UNVERIFIED_KEY;
		memcpy(sd->linkKey,ind->key,CCM_KEY_SIZE);
		TL_SCHEDULE_TASK(ss_apsmeVerifyKeyReq,p);
		need_free_buf = 0;

	}
	if(need_free_buf){
		zb_buf_free((zb_buf_t  *)p);
	}

}


#if defined ZB_ROUTER_ROLE  || defined ZLL_DEVICE_INITIATOR_CAPABLE
/**
   TC initialization
 */
_CODE_SS_ void ss_zdoTcInit(){

	g_zbNwkCtx.handle.is_tc = 1;
	ZB_IEEE_ADDR_COPY(ss_ib.trust_center_address, g_zbMacPib.extAddress);
	aps_ib.aps_authenticated = 1;

}

#endif  /* ZB_COORDINATOR_ROLE || ZLL_DEVICE_INITIATOR_CAPABLE*/


#if ZB_TEST_ENABLE
s32 ss_legacySupportCb(void *p){
/*	extern ev_time_event_t *testTimer;*/
	extern bool apsSecurityEn;
	bool tem = apsSecurityEn;
	apsSecurityEn = !tem;
	ss_apsmeUpdateDevReq(p);
	apsSecurityEn =  tem;
/*	TL_ZB_TIMER_CANCEL(&testTimer);
	testTimer = NULL;*/
	return -1;
}
#endif

#ifdef ZB_ROUTER_ROLE
_CODE_SS_ void ss_zdoNwkKeyUpdateReq(void *p){
	ss_apsmeTxKeyReq_t *req = p;
	req->keySeqNum = ss_ib.activeKeySeqNum + 1;
	u8 alternateKeyIndex = (ss_ib.activeSecureMaterialIndex + 1)%SECUR_N_SECUR_MATERIAL;
	memcpy(ss_ib.nwkSecurMaterialSet[alternateKeyIndex].key,req->key,16);
	ss_ib.nwkSecurMaterialSet[alternateKeyIndex].keySeqNum = req->keySeqNum;
	ss_ib.nwkSecurMaterialSet[alternateKeyIndex].keyType = req->keyType;

	TL_SCHEDULE_TASK(ss_apsmeTxKeyReq,p);
}

_CODE_SS_ void ss_zdoTxNwkKey(void *p, u8 *extAddr){
	ss_apsmeTxKeyReq_t *req = p;
	ZB_IEEE_ADDR_COPY(req->dstAddr, extAddr);

	req->keyType = SS_STANDARD_NETWORK_KEY;
	//device already has NWK key. Send empty key to it.
	memcpy(req->key, ss_ib.nwkSecurMaterialSet[ss_ib.activeSecureMaterialIndex].key, CCM_KEY_SIZE);

	req->keySeqNum = ss_ib.activeKeySeqNum;
	req->relayByParent = 0;
	TL_SCHEDULE_TASK(ss_apsmeTxKeyReq, p);
}


/****************************************************************************************************************
 * @brief	Child authentication procedure - see 4.6.3.2.2, which invoked from zdo_nlme_join_indication
 */

_CODE_SS_ void ss_zdoChildAuthStart(void *p){

	ss_zdoAuthReq_t ind;
	memcpy((u8 *)&ind,(u8 *)p,sizeof(ind));
	u8 updateDevStatus = ss_zdoGetUpdateDeviceStatus(ind.rejoinNwk, ind.secureRejoin);

#ifdef ZB_COORDINATOR_ROLE
	if(g_zbNwkCtx.handle.is_tc){
		ss_apsmeTxKeyReq_t *req = p;
		ZB_IEEE_ADDR_COPY(req->dstAddr, ind.devAddr);
		req->keyType = SS_STANDARD_NETWORK_KEY;
		//device already has NWK key. Send empty key to it.
		if(ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_NWKKEY){
			memset(req->key,0,CCM_KEY_SIZE);
			req->keySeqNum = 0;
		}else{
			memcpy(req->key, ss_ib.nwkSecurMaterialSet[ss_ib.activeSecureMaterialIndex].key, CCM_KEY_SIZE);
			req->keySeqNum = ss_ib.activeKeySeqNum;
		}
		req->relayByParent = ind.useParent;
		if(req->relayByParent){
			memcpy(req->partnerAddr,ind.srcAddr,8);
		}
		TL_SCHEDULE_TASK(ss_apsmeTxKeyReq, p);
  }
  else
#endif  //ZB_COORDINATOR_ROLE
  {

     /*4.6.3.2.1  Router Operation
     send UPDATE-DEVICE to TC*/
	if(ZB_IEEE_ADDR_IS_INVAILD(ss_ib.trust_center_address)){//Invalid TC address, distributed join

		if(ind.rejoinNwk){
			zb_buf_free((zb_buf_t *)p);
			return;
		}

		ss_apsmeTxKeyReq_t *req = p;
		ZB_IEEE_ADDR_COPY(req->dstAddr, ind.devAddr);
		req->keyType = SS_STANDARD_NETWORK_KEY;
		//device already has NWK key. Send empty key to it.
		if(ss_ib.preConfiguredKeyType == SS_PRECONFIGURED_NWKKEY){
			memset(req->key,0,CCM_KEY_SIZE);
			req->keySeqNum = 0;
		}else{
			memcpy(req->key, ss_ib.nwkSecurMaterialSet[ss_ib.activeSecureMaterialIndex].key, CCM_KEY_SIZE);
			req->keySeqNum = ss_ib.activeKeySeqNum;
		}
		req->relayByParent = 0;
		TL_SCHEDULE_TASK(ss_apsmeTxKeyReq, p);
	}else{
		ss_apsmeDevUpdateReq_t *req = (ss_apsmeDevUpdateReq_t *)p;
		req->status = updateDevStatus;
		memcpy(req->dstAddr, ss_ib.trust_center_address, 8);
		req->devShortAddr = ind.devShortAddr;
		memcpy(req->devAddr, ind.devAddr, 8);
		TL_SCHEDULE_TASK(ss_apsmeUpdateDevReq, p);
#if ZB_TEST_ENABLE
		extern u8 legacySupport;

		if(legacySupport){
	/*		extern ev_time_event_t *testTimer;
			if(testTimer!=NULL){
				TL_ZB_TIMER_CANCEL(&testTimer);
			}*/
			ss_apsmeDevUpdateReq_t *req2 = (ss_apsmeDevUpdateReq_t *)zb_buf_allocate();
			memcpy((u8 *)req2,(u8 *)req,sizeof(*req));
			//testTimer = TL_ZB_TIMER_SCHEDULE(ss_legacySupportCb,(void *)req2,TL_SUPERFRAMETIME_TO_US(2));
			testTimerManage(1,ss_legacySupportCb,(void *)req2,30*1000);
		}
#endif
	}
  }
}
#endif


_CODE_SS_ void ss_zdoNwkKeySwitch(u8 keySeqNum){
	u8 i = 0;
	u8 shift = (ss_ib.activeSecureMaterialIndex + 1) % SECUR_N_SECUR_MATERIAL;
	for(i = 0;i < SECUR_N_SECUR_MATERIAL;i++){
        if(ss_ib.nwkSecurMaterialSet[i].keySeqNum == keySeqNum){
            break;
        }
    }

	if(i == SECUR_N_SECUR_MATERIAL){
#ifdef ZB_COORDINATOR_ROLE
		if (g_zbNwkCtx.handle.is_tc){

#ifdef ZB_TC_GENERATES_KEYS
			//We are here if no key with such key number found. Generate new one.
			ss_zdoKeyGenerate(shift, keySeqNum);
#endif
			i = shift;
    }
#endif
	}
	if(i != SECUR_N_SECUR_MATERIAL){
		if(keySeqNum != ss_ib.activeKeySeqNum){
			ss_ib.activeSecureMaterialIndex = i;
			ss_ib.activeKeySeqNum = keySeqNum;
			ss_ib.prevOutgoingFrameCounter = ss_ib.outgoingFrameCounter;
			ss_ib.outgoingFrameCounter = 0;

			for(u8 i=0;i<SECUR_N_DEVICE_PAIRSET;i++)
				ss_ib.ssDeviceKeyPairSet[i].incomingFrmaeCounter = 0;

		}
	}else if(!g_zbNwkCtx.handle.is_tc){
#ifndef ZB_DISABLE_REJOIN_AFTER_SEC_FAIL
		TL_SCHEDULE_TASK(ss_zdoSecureRejoin,NULL);
#endif
		}
}

#ifdef ZB_ROUTER_ROLE

_CODE_SS_ static u16 ss_zdoGetUpdateDeviceStatus(u8 rejoinNetwork, u8 secureRejoin)
{
	u8 v = ((!!rejoinNetwork) << 1) | secureRejoin;
	if(!v){
		return SS_STANDARD_DEV_UNSECURED_JOIN;
	}else if(v == 3){
		return SS_STANDARD_DEV_SECURED_REJOIN;
	}else if(v == 2){
		return SS_STANDARD_DEV_TC_REJOIN;
	}else{
		return -1;
	}
}


_CODE_SS_ void ss_zdoUpdateDeviceIndicationHandle(void *p){

	ss_apsmeDevUpdateInd_t *ind = p;

	//if the dev is my old neighbor, delete it from neighbor table

	u8 free_buffer = 1;
	if(ind->status == SS_DEV_LEFT){
		//Here we assume in address map, the short-extAddr pair is correct
		u8 addrRef;
		if((tl_idxByExtAddr(&addrRef,ind->devAddr) != TL_RETURN_INVALID) ||
				(tl_idxByShortAddr(&addrRef,ind->devShortAddr) != TL_RETURN_INVALID)){
			tl_zbNwkAddrMapDelete(addrRef);

		}
	}else if(ind->status != SS_STANDARD_DEV_SECURED_REJOIN){
		//When a device is rejoining and secures the NWK rejoin request command with active NWK key, no further
		//authorization is required
		//SS_STANDARD_DEV_UNSECURED_JOIN || SS_STANDARD_DEV_TC_REJOIN
		if(((ind->status == SS_STANDARD_DEV_TC_REJOIN) &&(!ss_securityModeIsDistributed()))
				|| ((ind->status == SS_STANDARD_DEV_UNSECURED_JOIN) && ss_zdoAcceptNewDevAllow())){
			//Need add the device to address map here, otherwise APS layer security may be fail
			u8 indx;
			tl_zbNwkAddrMapAdd(ind->devShortAddr,ind->devAddr,&indx);
			ss_zdoAuthReq_t *req = p;
			req->useParent = 1;
			req->rejoinNwk = (ind->status == SS_STANDARD_DEV_TC_REJOIN);
			req->secureRejoin = 0;
			free_buffer = 0;
			ss_zdoChildAuthStart(p);
		}
	}
	if(free_buffer){
		zb_buf_free((zb_buf_t *)p);
	}
}


/***************************************************************************************************
 * @brief	Upon receipt of the APSME-REMOVE-DEVICE.indication primitive the ZDO
			shall be informed that the device referenced by the SrcAddress parameter is
			requesting that the child device referenced by the ChildAddress parameter be
			removed from the network.
 * @param	remove device cmd primitive
 */
_CODE_SS_ void ss_zdoRemoveDeviceInd(void *p){
	ss_apsDevRemoveInd_t *ri = p;
	if(!memcmp(ri->tcAddr,ss_ib.trust_center_address,8)){
		nlme_leave_req_t *lr = p;

		if(!memcmp(ri->childExtAddr,g_zbMacPib.extAddress,8)){//This cmd is directly for myself
			memset(lr->deviceAddr,0,8);
		}
		lr->removeChildren = 1;
		lr->rejoin = 0;
		tl_zbNwkNlmeLeaveRequest(p);
		return;

	}
	zb_buf_free((zb_buf_t *)p);
}
#endif//if defined router role


/*****************************************************************************************************************
 * @brief	External interface used to configure NWK key used for encryption and decryption
 * @param	key: key info
 * 			i: key index
 * @return	none
 */

_CODE_SS_ void ss_zdoNwkKeyConfigure(u8 *key, u8 i,u8 keyType)
{
  if (i >= SECUR_N_SECUR_MATERIAL){
	  TL_STALLMCUFORDEBUG();

  }else{
    memcpy(ss_ib.nwkSecurMaterialSet[i].key, key, CCM_KEY_SIZE);
    ss_ib.nwkSecurMaterialSet[i].keySeqNum = i;
    ss_ib.nwkSecurMaterialSet[i].keyType = keyType;
  }
}

_CODE_SS_ void ss_zdoLinkKeyConfigure(u8 *key,ss_keyAttributes_e keyAttr, ss_linkKeytype_e keyType, addrExt_t addr)
{
	 ss_dev_pair_set_t *tmp = ss_freeDevKeyPairGet();
	 if(tmp){

		memcpy(tmp->linkKey,key,CCM_KEY_SIZE);/* AIB */
		tmp->apsLinkKeyType = keyType;
		tmp->keyAttr = keyAttr;
		tmp->incomingFrmaeCounter = 0;
		tmp->outgoingFrameCounter = 0;
		ZB_IEEE_ADDR_COPY(tmp->device_address,addr);
		ss_devKeyPairSyn(SS_DEVKEYPAIR_SYNID_ALL);
	}
}

_CODE_SS_ void ss_zdoUseKey(u8 index){
	if (index >= SECUR_N_SECUR_MATERIAL){
		TL_STALLMCUFORDEBUG();
	}else{
		ss_ib.activeKeySeqNum = index;
		ss_ib.activeSecureMaterialIndex = index;
	}
}
_CODE_SS_ bool ss_keyIsEmpty(u8 *key){
  u8 i = 0;
  for (; i < CCM_KEY_SIZE && key[i] == 0; i++);
  return (bool)(i == CCM_KEY_SIZE);

}


_CODE_SS_ bool ss_keyPreconfigured(void ){
	return	!ss_keyIsEmpty(ss_ib.nwkSecurMaterialSet[ss_ib.activeSecureMaterialIndex].key);
}


_CODE_SS_ u8 *ss_zdoGetNwkKeyBySeqNum(u8 keySeqNum){

	u8 i = ss_ib.activeSecureMaterialIndex;

	u8 cnt = 0;


	while (cnt++ < SECUR_N_SECUR_MATERIAL && ss_ib.nwkSecurMaterialSet[i].keySeqNum != keySeqNum){
		i = (i + 1) % SECUR_N_SECUR_MATERIAL;
	}

	if (cnt > SECUR_N_SECUR_MATERIAL){
		return NULL;
	}
	return ss_ib.nwkSecurMaterialSet[i].key;
}



_CODE_SS_ void ss_zdoSecureRejoin(void ){
  //rejoin to current pan
  ZB_EXTPANID_COPY(aps_ib.aps_use_ext_panid, NWK_NIB().extPANId);
  aps_ib.aps_use_insecure_join = 0;
  if(zdo_nwk_rejoin_req(NLME_REJOIN_METHOD_REJOIN, 0) != TRUE){
	  TL_SCHEDULE_TASK(ss_zdoSecureRejoin,NULL);
  }
}


_CODE_SS_ void zdo_ssInfoSaveToFlash(){
#if NV_ENABLE
	nv_flashWrite(NV_APSZDOSS_IB, sizeof(ss_ib), (u8*)&ss_ib);
	nv_nwkFrameCountSaveToFlash(ss_ib.outgoingFrameCounter);
#endif
}

_CODE_SS_ u8 zdo_ssInfoInit(void){
	u8 ret = NV_ITEM_NOT_FOUND;
#if NV_ENABLE
	ret = nv_flashRead(NV_APSZDOSS_IB, sizeof(ss_ib), (u8*)&ss_ib);
#endif
	return ret;
}

_CODE_SS_ void zdo_ssInfoUpdate(void){
#if NV_ENABLE
	bdb_ssInfo2NV();
#endif
}

//_CODE_SS_ void ss_zdoInitSecurityState(ss_preconfiguredKey_e type,u8 *key, u8 keySeq, ss_linkKeytype_e type){
//	switch(type){
//	case	SS_PRECONFIGURED_UNIQUELLINKKEY:
//	{
//		ss_zdoLinkKeyConfigure(key,SS_PROVISIONAL_KEY,SS_UNIQUE_LINK_KEY,);
//	}
//	}
//
//}

/********************************************************************************************************
 * @brief	External used function for security service initialization
 *
 * @param	*nwkKey: parameter only used for TC, configured network key to be used in NWK layer security,
 * 						if NULL should use the default key
 * 			*linkKey: configured link key used during transport key procedure
 * 			keyType:	link key type used, global or private
 * 			enSecurity:	enable or disable security used
 * @return none
 */
_CODE_SS_ void ss_zdoInit(bool enSecurity,ss_preconfiguredKey_e type){
	if(zdo_ssInfoInit() != NV_SUCC){
		if(enSecurity){
			ss_ib.securityLevel = 5;
			ss_ib.secureAllFrames = TRUE;
			ss_ib.preConfiguredKeyType = type;
			aps_ib.aps_use_insecure_join = TRUE;/* AIB */
			NWK_NIB().managerAddr = 0x0000;/* NIB */
		}
	}else{
		u32 frameCnt;
		if(NV_SUCC == nv_nwkFrameCountFromFlash(&frameCnt)){
			ss_ib.outgoingFrameCounter = frameCnt;
		}
		ss_ib.outgoingFrameCounter += SS_UPDATE_FRAMECOUNT_THRES;
		aps_ib.aps_authenticated = TRUE;
		tl_neighborFrameCntReset();
	}
}

_CODE_SS_ void ss_securityModeSet(ss_securityMode_e m){
	if(m == SS_SEMODE_CENTRALIZED){
		ss_ib.tcPolicy.updateTCLKrequired = 1;
		ZB_IEEE_ADDR_ZERO(ss_ib.trust_center_address);
	}else if(m == SS_SEMODE_DISTRIBUTED){
		ss_ib.tcPolicy.updateTCLKrequired = 0;
		ZB_IEEE_ADDR_INVALID(ss_ib.trust_center_address);
	}
}
#endif

