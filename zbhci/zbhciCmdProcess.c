/********************************************************************************************************
 * @file     zbhci.c
 *
 * @brief	 Zigbee Host communication interface which responsible for receive data from lower layer and uplayer. And resolve
 * 			the received message
 *
 * @author
 * @date     July. 1, 2017
 *
 * @par      Copyright (c) 2016, Telink Semiconductor (Shanghai) Co., Ltd.
 *           All rights reserved.
 *
 *			 The information contained herein is confidential and proprietary property of Telink
 * 		     Semiconductor (Shanghai) Co., Ltd. and is available under the terms
 *			 of Commercial License Agreement between Telink Semiconductor (Shanghai)
 *			 Co., Ltd. and the licensee in separate contract or the terms described here-in.
 *           This heading MUST NOT be removed from this file.
 *
 * 			 Licensees are granted free, non-transferable use of the information in this
 *			 file under Mutual Non-Disclosure Agreement. NO WARRENTY of ANY KIND is provided.
 *
 *******************************************************************************************************/

#include "../../proj/tl_common.h"
#include "../include/zb_common.h"
#include "../zbapi/zb_api.h"
#include "../bdb/includes/bdb.h"
#include "../../zigbee/zcl/zcl_include.h"
#include "../bdb/includes/tlOTA.h"
#include "zbhci.h"
static u8 pushSt = 0;

const zbhciTxMode_e zbhciConvertSet[] = {
		ZBHCI_ADDRMODE_BOUND,
		ZBHCI_ADDRMODE_GROUP,
		ZBHCI_ADDRMODE_SHORT,
		ZBHCI_ADDRMODE_IEEE,
		ZBHCI_ADDRMODE_SHORT,
		ZBHCI_ADDRMODE_NOTX,
		ZBHCI_ADDRMODE_BOUND,
		ZBHCI_ADDRMODE_SHORT,
		ZBHCI_ADDRMODE_IEEE,
};



void zbhciTxClusterCmdAddrResolve(epInfo_t *dstEpInfo, u8 *srcEp, u8 **payload){
	memset((u8 *)dstEpInfo,0,sizeof(*dstEpInfo));

	dstEpInfo->dstAddrMode = **payload;
	(*payload)++;
	if((dstEpInfo->dstAddrMode<ZBHCI_ADDRMODE_BRC)&&(dstEpInfo->dstAddrMode != ZBHCI_ADDRMODE_GROUP)){
		dstEpInfo->txOptions |= APS_TX_OPT_ACK_TX;
	}
	dstEpInfo->profileId = 0x0104;//HA_PROFILE_ID
	dstEpInfo->dstAddrMode = zbhciConvertSet[dstEpInfo->dstAddrMode];
	if(dstEpInfo->dstAddrMode == APS_LONG_DSTADDR_WITHEP){
		ZB_IEEE_ADDR_REVERT(dstEpInfo->dstAddr.extAddr,*payload);
		(*payload) += EXT_ADDR_LEN;
	}else{
		COPY_BUFFERTOU16_BE(dstEpInfo->dstAddr.shortAddr,*payload);
		(*payload) += sizeof(u16);
	}
	*srcEp = **payload;
	(*payload)++;
	dstEpInfo->dstEp = **payload;
	(*payload)++;
}

void zbhciBlockReqPush(ota_imageBlockReq_t *req,u16 reqAddr, u8 seq,u8 srcEp){
	u8 buf[32];
	u8 *ptr = buf;
	*ptr = seq;

	*ptr++ = srcEp;

	*ptr++ = ZCL_CLUSTER_OTA>>8;
	*ptr++ = ZCL_CLUSTER_OTA;

	*ptr++ = 2;//Address mode is short
	COPY_U16TOBUFFER_BE(ptr,reqAddr);
	ptr += sizeof(u16);

	ZB_IEEE_ADDR_REVERT(ptr,req->reqNodeAddr);
	ptr += EXT_ADDR_LEN;

	COPY_U32TOBUFFER_BE(ptr,req->fileOffset);
	ptr += sizeof(u32);

	COPY_U32TOBUFFER_BE(ptr,req->fileVer);
	ptr += sizeof(u32);

	COPY_U16TOBUFFER_BE(ptr,req->imageType);
	ptr += sizeof(u16);

	COPY_U16TOBUFFER_BE(ptr,req->manuCode);
	ptr += sizeof(u16);


	*ptr++ = req->maxDataSize;
	*ptr++ = req->fc;
//	ZB_IEEE_ADDR_REVERT(ptr,req->reqNodeAddr);
//	ptr += EXT_ADDR_LEN;
//
//
//
//
//	COPY_U16TOBUFFER_BE(ptr,req->blockReqDelay);
//	ptr += sizeof(u16);
//	*ptr++ = req->maxDataSize;

	zbhciTx(ZBHCI_MSG_BLOCK_REQUEST,(ptr - buf),buf);
}
void zbhciGetPermitJoinSt(void *arg){
	u8 st = nwkPermitJoinEn();
	zbhciTx(ZBHCI_MSG_PERMIT_JOIN_ST_GET_RESPONSE,1,&st);
}
void zbhciStringConvert(u8 *src,u8 len){
	u8 tem;
	for(u8 i=0;i<(len/2);i++){
		tem = src[i];
		src[i] = src[len - i - 1];
		src[len - i - 1] = tem;
	}
}

void zbhciLeaveIndMsgPush(nlmeLeaveInd_t *ind){
	zbhciStringConvert(ind->device_address,8);
	zbhciTx(ZBHCI_MSG_LEAVE_INDICATION,sizeof(*ind),(u8 *)ind);
}
void zbhciDevCnfMsgPush(zdo_device_annce_req_t *req){
	hci_devAnncMsg_t am;
	am.shortAddrH = req->nwk_addr_local>>8;
	am.shortAddrL = req->nwk_addr_local;
	ZB_IEEE_ADDR_REVERT(am.extAddr,req->ieee_addr_local);
	am.mc = *((u8 *)&req->mac_capability);
	zbhciTx(ZBHCI_MSG_DEVICE_ANNOUNCE,sizeof(am),(u8 *)&am);
}


void zbhciMatchDescRspPush(zdo_matchDescRsp_user_t *req){
	hci_matchRsp_t mr;
	mr.shortAddrH = req->nwkAddr>>8;
	mr.shortAddrL = req->nwkAddr;
	mr.st = req->status;
	mr.seq = req->seq;
	mr.matchLen = req->matchLen;
	u8 i = 0;
	for(;(i<mr.matchLen) && (i<MAX_MATCHRSP_LEN);i++){
		mr.matchRes[i] = req->matchList[i];
	}
	u8 len = 5 + i;
	zbhciTx(ZBHCI_MSG_MATCH_DESCRIPTOR_RESPONSE,len,(u8 *)&mr);
}

void zbhciBindUnbindRspPush(zdo_bindUnbindRsp_user_t *rsp){

	u16 rspId = rsp->isBinding?(ZBHCI_MSG_BIND_RESPONSE):(ZBHCI_MSG_UNBIND_RESPONSE);
	zbhciTx(rspId,2,(u8 *)rsp);
}


void zbhciActiveEpRspMsgPush(zdo_activeEpRspUser_t *rsp){

	ZB_LEBESWAPU16(rsp->nwk_addr_interest);
	zbhciTx(ZBHCI_MSG_ACTIVE_ENDPOINT_RESPONSE,(sizeof(*rsp) - MAX_REQUESTED_CLUSTER_NUMBER + rsp->active_ep_count),(u8 *)rsp);
}

static u8 zbhciResolveAddrRspMsg(zdo_ieeeAddrRsp_user_t *rsp){
	u8 len = 12;
	ZB_LEBESWAP(rsp->ieee_addr_remote,EXT_ADDR_LEN);
	ZB_LEBESWAPU16(rsp->nwk_addr_remote);
	for(u8 i=0;(i<rsp->num_assoc_dev)&&(i<MAX_RSPNUM);i++){
		if(i==0){
			len++;
		}
		ZB_LEBESWAPU16(rsp->nwk_addr_assoc_dev_lst[i]);
		len += 2;
	}
	return len;
}
void zbhciIeeeAddrRspMsgPush(zdo_ieeeAddrRsp_user_t *rsp){
	u8 len = zbhciResolveAddrRspMsg(rsp);
	zbhciTx(ZBHCI_MSG_IEEE_ADDRESS_RESPONSE,len,(u8 *)rsp);
}

void zbhciNwkAddrRspMsgPush(zdo_ieeeAddrRsp_user_t *rsp){
	u8 len = zbhciResolveAddrRspMsg(rsp);
	zbhciTx(ZBHCI_MSG_NETWORK_ADDRESS_RESPONSE,len,(u8 *)rsp);
}

void zbhciNodeDescRspMsgPush(zdo_nodeDescRspUser_t *rsp){

	hci_nodeDescRspMsg_t nr;
	nr.sqn = rsp->seqNum;
	nr.st = rsp->st;
	COPY_U16TOBUFFER_BE(&nr.nwkAddrH,rsp->nwk_addr_interest);
	nr.manuCodeL = rsp->node_descriptor.mcL8;
	nr.manuCodeH = rsp->node_descriptor.mcH8;

	COPY_U16TOBUFFER_BE(&nr.maxRxSizeH,rsp->node_descriptor.max_in_tr_size);
	COPY_U16TOBUFFER_BE(&nr.maxTxSizeH,rsp->node_descriptor.max_out_tr_size);

	COPY_U16TOBUFFER_BE(&nr.servMaskH,rsp->node_descriptor.server_mask);

	nr.descCap = rsp->node_descriptor.desc_capability_field;
	nr.macCap = rsp->node_descriptor.mac_capability_flag;
	nr.maxBuffSize = rsp->node_descriptor.max_buff_size;
	COPY_U16TOBUFFER_BE(&nr.bfH,(u16 )(*((u16 *)&rsp->node_descriptor)));
	//nr.bfH = *((u8 *)&rsp->node_descriptor.logical_type);
	ZB_LEBESWAPU16(rsp->nwk_addr_interest);
	ZB_LEBESWAPU16(rsp->node_descriptor.max_in_tr_size);
	ZB_LEBESWAPU16(rsp->node_descriptor.max_out_tr_size);
	ZB_LEBESWAPU16(rsp->node_descriptor.server_mask);

	memcpy((u8 *)&nr,(u8 *)rsp,4);


	zbhciTx(ZBHCI_MSG_NODE_DESCRIPTOR_RESPONSE,sizeof(nr),(u8 *)&nr);
}
void zbhciSimpleDescRspMsgPush(zdo_simpleDescRsp_user_t *rsp){
	hci_simpleDescRspMsg_t sr;
	memset((u8 *)&sr,0,sizeof(sr));
	sr.sqn = rsp->seqNum;
	sr.st = rsp->st;
	u8 len = 13;
	if(sr.st == SUCCESS){
		COPY_U16TOBUFFER_BE(&sr.nwkAddrH,rsp->nwk_addr_interest);
		sr.msgLen = rsp->length;
		sr.ep = rsp->simple_descriptor.endpoint;
		COPY_U16TOBUFFER_BE(&sr.profileIdH,rsp->simple_descriptor.app_profile_id);
		COPY_U16TOBUFFER_BE(&sr.deviceIdH,rsp->simple_descriptor.app_dev_id);
		sr.appVer = rsp->simple_descriptor.app_dev_ver;
		sr.inputClstNum = rsp->simple_descriptor.app_in_cluster_count;
		u8 *ptr = sr.payload;
		for(u8 i=0; i<sr.inputClstNum && i<MAX_REQ_CLST_NUM;i++){
			COPY_U16TOBUFFER_BE(ptr,rsp->simple_descriptor.app_in_cluster_lst[i]);
			ptr += 2;
		}
		*ptr++ = rsp->simple_descriptor.app_out_cluster_count;
		for(u8 i=0; i<rsp->simple_descriptor.app_out_cluster_count && i<MAX_REQ_CLST_NUM;i++){
			COPY_U16TOBUFFER_BE(ptr,rsp->simple_descriptor.app_out_cluster_lst[i]);
			ptr += 2;
		}
		len = rsp->length + 5;
	}

	zbhciTx(ZBHCI_MSG_SIMPLE_DESCRIPTOR_RESPONSE,len ,(u8 *)&sr);
}
void zbhciNwkStartCnfMsgDeliver(u8 st){
	if(pushSt){
		hci_nwkStartCnfMsg_t cnf;
		cnf.st = st;
		cnf.channel = g_zbMacPib.phyChannelCur;
		cnf.shortAddrH = g_zbMacPib.shortAddress>>8;
		cnf.shortAddrL = g_zbMacPib.shortAddress;
		ZB_IEEE_ADDR_REVERT(cnf.extAddr,g_zbMacPib.extAddress);
		zbhciTx(ZBHCI_MSG_NETWORK_JOINED_FORMED,sizeof(cnf),(u8 *)&cnf);
		pushSt = 0;
	}
}


void zbhciProcessIncommingSerialCmd(u16 msgType, u16 msgLen, u8 *p){
	u8 ret[4] = {0,0,0,0};
	u8 seqNum = 0;//pdu tx seq num
	u8 st = 0;
	u16 targetAddr;
	switch (msgType)
	{
		case(ZBHCI_MSG_GET_VERSION):
		{
			u32     u32Version = CURRENT_FILE_VERSION;
			ret[0] = st;
			ret[1] =  seqNum;
			COPY_U16TOBUFFER_BE(ret+2,msgType);
			zbhciTx (ZBHCI_MSG_STATUS,sizeof(ret),ret);
			zbhciTx (ZBHCI_MSG_VERSION_LIST,sizeof(u32),(u8*) &u32Version );
			return;
		}
		break;
		case (ZBHCI_MSG_SET_EXT_PANID):
		{
			st  = zb_setExtPanId(p);
		}
		break;

		case(ZBHCI_MSG_SET_CHANNELMASK):
		{
			u32    u32Value;
			COPY_BUFFERTOU32_BE(u32Value,p);
			st =  zb_setApsChannelMask(u32Value);
			if(st == ZDO_SUCCESS){
				tl_zbMacChannelSet(zdo_channel_page2num(u32Value));
			}
		}
		break;

		case (ZBHCI_MSG_RESET):
		{
			TL_SCHEDULE_TASK(zb_resetDevice,NULL);
		}
		break;

		case (ZBHCI_MSG_ERASE_PERSISTENT_DATA):
		{
			TL_SCHEDULE_TASK(zb_resetDevice2FN,NULL);
		}
		break;

		case (ZBHCI_MSG_PERMIT_JOIN_ST_GET):
		{
			TL_SCHEDULE_TASK(zbhciGetPermitJoinSt,NULL);
		}
		break;
		case (ZBHCI_MSG_START_NETWORK):
		{
			pushSt = 1;
			if(g_bdbAttrs.nodeIsOnANetwork){
				zbhciNwkStartCnfMsgDeliver(BDB_COMMISSION_STA_SUCCESS);
			}else{
				bdb_topLevelCommissioning(BDB_COMMISSIONING_ROLE_TARGET);
			}
		}
		break;

		case(ZBHCI_MSG_PERMIT_JOINING_REQUEST):
		{
			COPY_BUFFERTOU16_BE(targetAddr,p);
			st =  zb_mgmtPermitJoinReqTx(targetAddr,p[2],p[3],NULL);
		}
		break;
		case (ZBHCI_MSG_MANAGEMENT_LEAVE_REQUEST):
		{
			addrExt_t    u64LookupAddress;
			COPY_BUFFERTOU16_BE(targetAddr,p);
			ZB_IEEE_ADDR_REVERT(u64LookupAddress,p+2);
			st = zb_zdpMgmtLeaveReq(targetAddr,u64LookupAddress,p[10],p[11],&seqNum);
		}
		break;

		case (ZBHCI_MSG_NETWORK_REMOVE_DEVICE):
		{
			addrExt_t    u64LookupAddress, u64DevAddr;
			ZB_IEEE_ADDR_REVERT(u64LookupAddress,p);
			ZB_IEEE_ADDR_REVERT(u64DevAddr,p+8);
			st = zb_zdpRemoveDevReq(u64LookupAddress,u64DevAddr);
		}
		break;

		case ZBHCI_MSG_LEAVE_REQUEST:
		{
			addrExt_t    u64LookupAddress;
			u8 idx;
			ZB_IEEE_ADDR_REVERT(u64LookupAddress,p);
			if(tl_zbShortAddrByExtAddr(&targetAddr,u64LookupAddress,&idx) == TL_RETURN_INVALID){
				st  = APS_STATUS_ILLEGAL_REQUEST;
			}else{
				st = zb_zdpMgmtLeaveReq(targetAddr,u64LookupAddress,p[8],p[9],&seqNum);
			}
		}
		break;
		case (ZBHCI_MSG_MATCH_DESCRIPTOR_REQUEST):
		{
			zdo_match_descriptor_req_t req;
			u8 *ptr = p;
			u8     i                 =  0 ;
			req.num_out_clusters =  p [ ( ( p [ 4 ] * ( sizeof ( u16 ) ) ) + 5) ];
			COPY_BUFFERTOU16_BE(req.nwk_addr_interest,ptr);
			ptr += 2;
			COPY_BUFFERTOU16_BE(req.profile_id,ptr);
			ptr += 2;
			req.num_in_clusters  = *ptr++;

			while ((i < MAX_REQUESTED_CLUSTER_NUMBER)  && (i < req.num_in_clusters))
			{
				COPY_BUFFERTOU16_BE(req.in_cluster_lst[ i ],ptr);
				ptr += 2;
				i++;
			}

			req.num_out_clusters  = *ptr++;
			i =  0 ;
			while ( ( i < MAX_REQUESTED_CLUSTER_NUMBER )  && ( i < req.num_out_clusters ) )
			{
				COPY_BUFFERTOU16_BE(req.out_cluster_lst[ i ],ptr);
				ptr += 2;
				i++;
			}

			st  =  zb_zdoMatchDescReq(&req,zbhciMatchDescRspPush);

		}
		break;
		case (ZBHCI_MSG_BIND):
		case (ZBHCI_MSG_UNBIND):
		{
			zdo_bind_req_t req;
			u8 *ptr = p;

			ZB_IEEE_ADDR_REVERT(req.src_addr,ptr);
			ptr += EXT_ADDR_LEN;
			req.src_endpoint = *ptr++;

			req.cid16_h = *ptr++;
			req.cid16_l = *ptr++;
			req.dst_addr_mode = *ptr++;

			if(req.dst_addr_mode == 0x3)
			{
				ZB_IEEE_ADDR_REVERT(req.dst_ext_addr,ptr);
				ptr += EXT_ADDR_LEN;
				req.dst_endpoint =  *ptr++;
			}else{
				COPY_BUFFERTOU16_BE(req.dst_group_addr,ptr);
				ptr += 2;
			}
			st = zb_zdpBindUnbindReq((msgType == ZBHCI_MSG_BIND),&req,zbhciBindUnbindRspPush);

		}
		break;


		case (ZBHCI_MSG_ACTIVE_ENDPOINT_REQUEST):
		{
			COPY_BUFFERTOU16_BE(targetAddr,p);
			st = zb_zdoActiveEpReq(targetAddr,zbhciActiveEpRspMsgPush);
		}
		break;

		case (ZBHCI_MSG_IEEE_ADDRESS_REQUEST):
		{
			zdo_ieee_addr_req_t req;

			COPY_BUFFERTOU16_BE(targetAddr,p);
			COPY_BUFFERTOU16_BE(req.nwk_addr_interest,p+2);
			req.req_type = p[4];
			req.start_index = p[5];
			st   =  zb_ieeeAddrReq(targetAddr,&req,zbhciIeeeAddrRspMsgPush);
		}
		break;

		case (ZBHCI_MSG_NETWORK_ADDRESS_REQUEST):
		{
			zdo_nwk_addr_req_t req;

			//zb_nwkAddrReq(u16 dstShortAddr, zdo_nwk_addr_req_t *pReq,zdo_callback indCb)
			COPY_BUFFERTOU16_BE(targetAddr,p);
			ZB_IEEE_ADDR_REVERT(req.ieee_addr_interest,p+2);
			req.req_type = p[10];
			req.start_index = p[11];
			st  =  zb_nwkAddrReq( targetAddr,&req,zbhciNwkAddrRspMsgPush);
		}
		break;

		case (ZBHCI_MSG_NODE_DESCRIPTOR_REQUEST):
		{

			zdo_node_descriptor_req_t req;
			COPY_BUFFERTOU16_BE(req.nwk_addr_interest,p);
			st = zb_zdoNodeDescReq (&req,zbhciNodeDescRspMsgPush);
		}
		break;

		case (ZBHCI_MSG_SIMPLE_DESCRIPTOR_REQUEST):
		{
			zdo_simple_descriptor_req_t req;
			COPY_BUFFERTOU16_BE(req.nwk_addr_interest,p);
			req.endpoint = p[2];

			st =  zb_zdoSimpleDescReq(&req,zbhciSimpleDescRspMsgPush);
		}
		break;

		/* level cluster commands */
		case (ZBHCI_MSG_MOVE_TO_LEVEL):
		case (ZBHCI_MSG_MOVE_TO_LEVEL_ONOFF):
		case (ZBHCI_MSG_MOVE_STEP):
		case (ZBHCI_MSG_MOVE_STOP_ONOFF):
		{
			zbhci_zclLevelCtrlCmdHandle(msgType,p,&seqNum);

		}
		break;
		case (ZBHCI_MSG_ONOFF_NOEFFECTS):
		{

			st = zbhci_zclOnoffCmdHandle(p,&seqNum);
		}
		break;

		case ZBHCI_MSG_IMAGE_NOTIFY:
		{
			epInfo_t dstEp;
			u8 srcEp;
			u8 *payLoad = p;
			zbhciTxClusterCmdAddrResolve(&dstEp,&srcEp,&payLoad);
			ota_imageNotify_t in;
			in.payloadType = *payLoad++;
			COPY_BUFFERTOU32_BE(in.newFileVer,payLoad);
			payLoad += sizeof(u32);
			COPY_BUFFERTOU16_BE(in.imageType,payLoad);
			payLoad += sizeof(u16);
			COPY_BUFFERTOU16_BE(in.manuCode,payLoad);
			payLoad += sizeof(u16);
			in.queryJitter = *payLoad++;
			st = ota_serverImageNotifyTx(srcEp,&dstEp,&in);     // *psImageNotifyCommand
		}
		break;
		case ZBHCI_MSG_LOAD_NEW_IMAGE:
		{
			DEBUG(DEBUG_OTA,"Load new image info to OTA server\n");
			ota_hdrFields oh;
			u8 *ptr = p + 3;
			COPY_BUFFERTOU32_BE(oh.otaUpgradeFileID,ptr);
			ptr += sizeof(u32);
			COPY_BUFFERTOU16_BE(oh.otaHdrVer,ptr);
			ptr += sizeof(u16);
			COPY_BUFFERTOU16_BE(oh.otaHdrLen,ptr);
			ptr += sizeof(u16);
			COPY_BUFFERTOU16_BE(oh.otaHdrFC,ptr);
			ptr += sizeof(u16);
			COPY_BUFFERTOU16_BE(oh.manufaurerCode,ptr);
			ptr += sizeof(u16);
			COPY_BUFFERTOU16_BE(oh.imageType,ptr);
			ptr += sizeof(u16);
			COPY_BUFFERTOU32_BE(oh.fileVer,ptr);
			ptr += sizeof(u32);
			COPY_BUFFERTOU16_BE(oh.zbStackVer,ptr);
			ptr += sizeof(u16);

			for(u8 i=0;i<32;i++){
				oh.otaHdrString[i] = *ptr++;
			}
			COPY_BUFFERTOU32_BE(oh.totalImageSize,ptr);
			ptr += sizeof(u32);
			oh.securityCredVer = *ptr++;
			ZB_IEEE_ADDR_REVERT(oh.fileDest,ptr);
			ptr += EXT_ADDR_LEN;
			COPY_BUFFERTOU16_BE(oh.minHdrVer,ptr);
			ptr += sizeof(u16);
			COPY_BUFFERTOU16_BE(oh.maxHdrVer,ptr);
			ptr += sizeof(u16);
			st = ota_loadImageInfo(&oh);
		}
		break;

		case ZBHCI_MSG_BLOCK_SEND:
		{
			DEBUG(DEBUG_OTA,"Receive block info from host\n");
			printfArray(p,msgLen);

			u8 len = sizeof(ota_imageBlcokRspSuccess) - 4 + p[18];
			ota_imageBlockRsp_t *rsp =(ota_imageBlockRsp_t *)ev_buf_allocate(len);
			if(!rsp){
				return;
			}

			rsp->rspSuccess.st = p[4];

			COPY_BUFFERTOU32_BE(rsp->rspSuccess.fileOffset,(p+6));
			COPY_BUFFERTOU32_BE(rsp->rspSuccess.fileVer,(p+10));
			COPY_BUFFERTOU16_BE(rsp->rspSuccess.imageType,(p+14));
			COPY_BUFFERTOU16_BE(rsp->rspSuccess.manuCode,(p+16));
			rsp->rspSuccess.dataSize = p[18];
			memcpy(rsp->rspSuccess.data,(p+19),p[18]);

			epInfo_t ep;
			memset((u8 *)&ep,0,sizeof(ep));
			ep.profileId = 0x0104;
			ep.radius = 10;
			ep.dstAddrMode = APS_SHORT_DSTADDR_WITHEP;
			ep.dstEp = p[5];
			ep.dstAddr.shortAddr = p[1] + p[0]<<8;

			u8 handle = af_handleGet();
			st = tl_zclCmdSend(p[3], &ep, ZCL_CLUSTER_OTA, OTA_CMD_IMAGEBLOCK_RSP, TRUE,
					ZCL_FRAME_SERVER_CLIENT_DIR, TRUE, 0, ZCL_SEQ_NUM, len, (u8 *)rsp, handle);
			ev_buf_free((u8 *)rsp);
		}
		break;

#if 0

#ifdef FULL_FUNC_DEVICE
		case (ZBHCI_MSG_START_SCAN):
		{
			APP_vControlNodeScanStart ( ) ;
		}
		break;
#endif

		case (ZBHCI_MSG_ADD_AUTHENTICATE_DEVICE):
		{
			APP_tsEvent    sAppEvent;
			u8          i = 0;

			sAppEvent.eType                            =  APP_E_EVENT_ENCRYPT_SEND_KEY;
			sAppEvent.uEvent.sEncSendMsg.u64Address    =  ZNC_RTN_U64 ( p, 0 );

			st    =  ZPS_bAplZdoTrustCenterSetDevicePermissions( sAppEvent.uEvent.sEncSendMsg.u64Address,
																   ZPS_DEVICE_PERMISSIONS_ALL_PERMITED );
			if(st == ZPS_E_SUCCESS)
			{
				while( i < 16)
				{
					sAppEvent.uEvent.sEncSendMsg.uKey.au8[i] = p[ 8 + i ];
					i++;
				}
				ZQ_bQueueSend ( &APP_msgAppEvents, &sAppEvent);
			}
		}
		break;

		case (ZBHCI_MSG_OUTOFBAND_COMMISSIONING_DATA_REQ):
		{
			u8                              i = 0;
			APP_tsEvent                        sAppEvent;

			sAppEvent.eType                            		=  APP_E_EVENT_OOB_COMMISSIONING_DATA;
			sAppEvent.uEvent.sOOBCommissionData.u64Address	=  ZNC_RTN_U64 (p, 0);
			while(i < 16)
			{
				sAppEvent.uEvent.sOOBCommissionData.au8InstallKey[i] = p[8+i];
				i++;
			}
			ZQ_bQueueSend (&APP_msgAppEvents, &sAppEvent);
		}
		break;

		case (ZBHCI_MSG_UPDATE_AUTHENTICATE_DEVICE):
		{
			addrExt_t         u64Address;

			u64Address    =  ZNC_RTN_U64 ( p, 0 );
			st      =  ZPS_bAplZdoTrustCenterSetDevicePermissions( u64Address,
																		 p[8] );

		}
		break;

		case (ZBHCI_MSG_NETWORK_WHITELIST_ENABLE):
		{
			bBlackListEnable    =  p [ 0 ] ;
			ZPS_vTCSetCallback( APP_bSendHATransportKey );
		}
		break;




#ifdef FULL_FUNC_DEVICE
		case (ZBHCI_MSG_TOUCHLINK_FACTORY_RESET):
		{
			sEvent.eType             =  BDB_E_ZCL_EVENT_TL_START;
			bSendFactoryResetOverAir =  TRUE;
			BDB_vZclEventHandler ( &sEvent );

		}
		break;

		case (ZBHCI_MSG_ZLL_FACTORY_NEW):
		{
			if (sZllState.u8DeviceType != ZPS_ZDO_DEVICE_COORD)
			{
				ZPS_tsNwkNib *psNib    =  ZPS_psAplZdoGetNib ( );

				u32OldFrameCtr    =  psNib->sTbl.u32OutFC;
				APP_vFactoryResetRecords ( );
			}
		}
		break;

		case (ZBHCI_MSG_INITIATE_TOUCHLINK):
		{
			if(sZllState.u8DeviceType != ZPS_ZDO_DEVICE_COORD)
			{
				APP_vAppAddGroup( 0 , FALSE );
				sEvent.eType              =  BDB_E_ZCL_EVENT_TL_START;
				BDB_vZclEventHandler ( &sEvent );
			}
			else
			{
				st            =  ZBHCI_MSG_STATUS_BUSY;
				bProcessMessages    =  FALSE;
			}

		}
		break;
#endif
		case (ZBHCI_MSG_SEND_RAW_APS_DATA_PACKET):
		{
			ZPS_tsAfProfileDataReq    sAfProfileDataReq;
			u8                     u8DataLength;

			sAfProfileDataReq.uDstAddr.u16Addr    =  ZNC_RTN_U16 ( p, 1 );
			sAfProfileDataReq.u16ClusterId        =  ZNC_RTN_U16 ( p, 5 );
			sAfProfileDataReq.u16ProfileId        =  ZNC_RTN_U16 ( p, 7 );
			sAfProfileDataReq.eDstAddrMode        =  p[0];
			sAfProfileDataReq.u8SrcEp             =  p[3];
			sAfProfileDataReq.u8DstEp             =  p[4];
			sAfProfileDataReq.eSecurityMode       =  p[9];
			sAfProfileDataReq.u8Radius            =  p[10];
			u8DataLength                          =  p[11];

			st                              =  APP_eApsProfileDataRequest ( &sAfProfileDataReq,
																				  &p[12],
																				  u8DataLength,
																				  &seqNum );
		}
		break;

		case (ZBHCI_MSG_COMPLEX_DESCRIPTOR_REQUEST):
		{
			u16    u16PayloadAddress;

			u16TargetAddress     =  ZNC_RTN_U16 ( p, 0 );
			u16PayloadAddress    =  ZNC_RTN_U16 ( p, 2 );

			st    =  APP_eZdpComplexDescReq ( u16TargetAddress,
													u16PayloadAddress,
													&seqNum );
		}
		break;




		case (ZBHCI_MSG_POWER_DESCRIPTOR_REQUEST):
		{
			u16TargetAddress    =  ZNC_RTN_U16 ( p, 0 );
			st            =  APP_eZdpPowerDescReq ( u16TargetAddress,
														  &seqNum );
		}
		break;

		case (ZBHCI_MSG_MANAGEMENT_NETWORK_UPDATE_REQUEST):
		{
			u32    u32ChannelMask;
			u8     u8ScanDuration;
			u8     u8ScanCount;
			u16    u16NwkManagerAddr;

			u16TargetAddress    =  ZNC_RTN_U16 ( p, 0 );
			u32ChannelMask      =  ZNC_RTN_U32 ( p, 2 );
			u8ScanDuration      =  p[6];
			u8ScanCount         =  p[7];
			u16NwkManagerAddr   =  ZNC_RTN_U16 ( p, 8);

			st        =  APP_eZdpMgmtNetworkUpdateReq ( u16TargetAddress,
															  u32ChannelMask,
															  u8ScanDuration,
															  u8ScanCount,
															  &seqNum,
															  u16NwkManagerAddr);
		}
		break;

		case (ZBHCI_MSG_SYSTEM_SERVER_DISCOVERY):
		{
			u16    u16ServerMask;

			u16TargetAddress    =  ZNC_RTN_U16 ( p, 0 );
			u16ServerMask       =  ZNC_RTN_U16 ( p, 2 );

			st        =  APP_eZdpSystemServerDiscovery ( u16ServerMask,
														   &seqNum );
		}
		break;

		case (ZBHCI_MSG_MANAGEMENT_LQI_REQUEST):
		{
		   u8    u8StartIndex;

		   u16TargetAddress    =  ZNC_RTN_U16 ( p, 0 );
		   u8StartIndex        =  p[2];
		   st            = APP_eZdpMgmtLqiRequest ( u16TargetAddress,
														  u8StartIndex,
														  &seqNum );

		}
		break;

		case (ZBHCI_MSG_USER_DESC_SET):
		{
			u16    u16AddrInterest;

			u16TargetAddress    =  ZNC_RTN_U16 ( p , 0 );
			u16AddrInterest     =  ZNC_RTN_U16 ( p , 2 );

			st    =  APP_eSetUserDescriptorReq ( u16TargetAddress,
													   u16AddrInterest,
													   &p[5],
													   p[4],
													   &seqNum );
		}
		break;

		case (ZBHCI_MSG_USER_DESC_REQ):
		{
			u16    u16AddrInterest;

			u16TargetAddress    =  ZNC_RTN_U16 ( p , 0 );
			u16AddrInterest     =  ZNC_RTN_U16 ( p , 2 );

			st    =  APP_eZdpUserDescReq ( u16TargetAddress,
												 u16AddrInterest,
												 &seqNum );
		}
		break;
		case ZBHCI_MSG_MANY_TO_ONE_ROUTE_REQUEST:
		{
			st    = ZPS_eAplZdoManyToOneRouteRequest( p[3],        // bCacheRoute
															p[4] );        // u8Radius
		}
		break;

		/* Group cluster commands */
		case (ZBHCI_MSG_ADD_GROUP):
		{
			if ( 0x0000 == u16TargetAddress )
			{
				u16          u16GroupId;
				u8           i;
				ZPS_tsAplAib    *psAplAib = ZPS_psAplAibGetAib();

				u16GroupId      =  ZNC_RTN_U16 ( p, 5 );

				vLog_Printf ( TRACE_APP, LOG_DEBUG, "\nAdd Group ID: %x", u16GroupId );
				vLog_Printf ( TRACE_APP, LOG_DEBUG, "\nAdd EndPoint: %x", p[4] );

				/* Request to add the bridge to a group, no name supported... */
				st    = ZPS_eAplZdoGroupEndpointAdd ( u16GroupId,
															p [ 4 ] );

				for ( i = 0; i < psAplAib->psAplApsmeGroupTable->u32SizeOfGroupTable; i++ )
				{
					vLog_Printf ( TRACE_APP, LOG_DEBUG, "\nGroup ID: %x",
										  psAplAib->psAplApsmeGroupTable->psAplApsmeGroupTableId[i].u16Groupid );
					vLog_Printf ( TRACE_APP, LOG_DEBUG, "\nEndPoint 0: %x",
										  psAplAib->psAplApsmeGroupTable->psAplApsmeGroupTableId[i].au8Endpoint[0] );
				}
			}
			else
			{
				tsCLD_Groups_AddGroupRequestPayload    sRequest;

				sRequest.u16GroupId        =  ZNC_RTN_U16 ( p, 5 );
				sRequest.sGroupName.u8Length       =  0;
				sRequest.sGroupName.u8MaxLength    =  0;
				sRequest.sGroupName.pu8Data    =  (u8*)"";

				st    =  eCLD_GroupsCommandAddGroupRequestSend( p [ 3 ],
																	  p [ 4 ],
																	  &sAddress,
																	  &seqNum,
																	  &sRequest );
			}
		}
		break;

		case (ZBHCI_MSG_REMOVE_GROUP):
		{
			if ( 0x0000 == u16TargetAddress )
			{
				u16    u16GroupId;

				u16GroupId    =  ZNC_RTN_U16 ( p, 5 );

				/* Request is for the control bridge */
				st    =  ZPS_eAplZdoGroupEndpointRemove ( u16GroupId,
																p [ 4 ] );
			}
			else
			{
				/* Request is for a remote node */
				tsCLD_Groups_RemoveGroupRequestPayload    sRequest;

				sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
				st =  eCLD_GroupsCommandRemoveGroupRequestSend( p [ 3 ],
																	  p [ 4 ] ,
																	  &sAddress,
																	  &seqNum,
																	  &sRequest);
			}
		}
		break;

		case (ZBHCI_MSG_REMOVE_ALL_GROUPS):
		{
			if (0x0000 == u16TargetAddress)
			{
				vLog_Printf ( TRACE_APP, LOG_DEBUG, "\nRemove All Groups" );
				vLog_Printf ( TRACE_APP, LOG_DEBUG, "\nDst EndPoint: %x", p [ 4 ] );

				/* Request is for the control bridge */
				st =  ZPS_eAplZdoGroupAllEndpointRemove( p [ 4 ] );
			}
			else
			{
				tsZCL_Address    sAddress;
				u16           u16TargetAddress;

				u16TargetAddress                =  ZNC_RTN_U16 ( p , 1 );
				sAddress.eAddressMode           =  p[0];
				sAddress.uAddress.u16DestinationAddress =  u16TargetAddress;
				st = eCLD_GroupsCommandRemoveAllGroupsRequestSend(p [ 3 ],
																		p [ 4 ],
																		&sAddress,
																		&seqNum );
			}
		}
		break;

		case (ZBHCI_MSG_ADD_GROUP_IF_IDENTIFY):
		{
			tsCLD_Groups_AddGroupRequestPayload    sRequest;

			sRequest.u16GroupId                =  ZNC_RTN_U16 ( p, 5 );
			sRequest.sGroupName.u8Length       =  0;
			sRequest.sGroupName.u8MaxLength    =  0;
			sRequest.sGroupName.pu8Data        =  (u8*)"";

			st =  eCLD_GroupsCommandAddGroupIfIdentifyingRequestSend ( p [ 3 ],
																			 p [ 4 ],
																			 &sAddress,
																			 &seqNum,
																			 &sRequest );
		}
		break;

		case (ZBHCI_MSG_VIEW_GROUP):
		{
			tsCLD_Groups_ViewGroupRequestPayload    sRequest;

			sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
			st    =  eCLD_GroupsCommandViewGroupRequestSend ( p[3],
																	p[4],
																	&sAddress,
																	&seqNum,
																	&sRequest );
		}
		break;

		case (ZBHCI_MSG_GET_GROUP_MEMBERSHIP):
		{
			tsCLD_Groups_GetGroupMembershipRequestPayload    sRequest;
			u16                                           au16GroupList [ 10 ];
			u8                                            i = 0 ;

			while ( ( i < 10 ) &&
					( i < p [ 5 ] ) )
			{
				au16GroupList[i]    =  ZNC_RTN_U16( p, ( 6 + ( i * 2) ) );
				i++;
			}
			sRequest.pi16GroupList    =  ( zint16* ) au16GroupList;
			sRequest.u8GroupCount     =  p [ 5 ];

			st    =  eCLD_GroupsCommandGetGroupMembershipRequestSend ( p [ 3 ],
																			 p [ 4 ],
																			 &sAddress,
																			 &seqNum,
																			 &sRequest );
		}
		break;

	 /*Scenes Cluster */
		case (ZBHCI_MSG_ADD_SCENE):
		{
			u8                                 au8Data [ 16 ];
			u8                                 i = 0;
			tsCLD_ScenesAddSceneRequestPayload    sRequest;

			sRequest.u16GroupId                =  ZNC_RTN_U16 ( p, 5 );
			sRequest.u8SceneId                 =  p[7];
			sRequest.u16TransitionTime         =  ZNC_RTN_U16 ( p, 8 );
			sRequest.sSceneName.u8Length       =  p[10];
			sRequest.sSceneName.u8MaxLength    =  p[11];

			while ( ( i < 16 ) &&
					( i < sRequest.sSceneName.u8Length ) )
			{
				au8Data [ i ]    =  p[ 12 + i ];
				i++;
			}
			sRequest.sSceneName.pu8Data       =  au8Data;
			sRequest.sExtensionField.pu8Data      =  NULL;
			sRequest.sExtensionField.u16Length    =  0;

			st    =  eCLD_ScenesCommandAddSceneRequestSend ( p [ 3 ],
																   p [ 4 ],
																   &sAddress,
																   &seqNum,
																   &sRequest );
		}
		break;

		case (ZBHCI_MSG_REMOVE_SCENE):
		{
			tsCLD_ScenesRemoveSceneRequestPayload    sRequest;

			sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
			sRequest.u8SceneId     =  p[7];
			st               =  eCLD_ScenesCommandRemoveSceneRequestSend ( p [ 3 ],
																				 p [ 4 ],
																				 &sAddress,
																				 &seqNum,
																				 &sRequest );
		}
		break;

		case (ZBHCI_MSG_VIEW_SCENE):
		{
			tsCLD_ScenesViewSceneRequestPayload    sRequest;

			sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
			sRequest.u8SceneId     =  p[7];
			st               =  eCLD_ScenesCommandViewSceneRequestSend ( p [ 3 ],
																			   p [ 4 ],
																			   &sAddress,
																			   &seqNum,
																			   &sRequest );
		}
		break;


		case (ZBHCI_MSG_REMOVE_ALL_SCENES):
		{
			tsCLD_ScenesRemoveAllScenesRequestPayload    sRequest;

			sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
			st               =  eCLD_ScenesCommandRemoveAllScenesRequestSend ( p [ 3 ],
																					 p [ 4 ],
																					 &sAddress,
																					 &seqNum,
																					 &sRequest );
		}
		break;

		case (ZBHCI_MSG_STORE_SCENE):
		{
			tsCLD_ScenesStoreSceneRequestPayload    sRequest;

			sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
			sRequest.u8SceneId     =  p[7];
			st     =  eCLD_ScenesCommandStoreSceneRequestSend ( p [ 3 ],
																	  p [ 4 ],
																	  &sAddress,
																	  &seqNum,
																	  &sRequest );
		}
		break;

		case (ZBHCI_MSG_RECALL_SCENE):
		{
			tsCLD_ScenesRecallSceneRequestPayload    sRequest;

			sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
			sRequest.u8SceneId     =  p[7];
			st    =  eCLD_ScenesCommandRecallSceneRequestSend ( p [ 3 ],
																	  p [ 4 ],
																	  &sAddress,
																	  &seqNum,
																	  &sRequest );
		}
		break;
#ifdef  CLD_SCENES_CMD_ENHANCED_ADD_SCENE
		case (ZBHCI_MSG_ADD_ENHANCED_SCENE):
		{
			tsCLD_ScenesEnhancedAddSceneRequestPayload    sRequest;

			sRequest.u16GroupId                   =  ZNC_RTN_U16 ( p, 5 );
			sRequest.u8SceneId                    =  p[7];
			sRequest.u16TransitionTime100ms       =  ZNC_RTN_U16 ( p, 8 );
			sRequest.sExtensionField.u16Length    =  ZNC_RTN_U16 ( p, 9 );
			sRequest.sExtensionField.u16MaxLength =  ZNC_RTN_U16 ( p, 11 );
			sRequest.sExtensionField.pu8Data      =  &p[ 12 ];
			st    =  eCLD_ScenesCommandEnhancedAddSceneRequestSend ( p [ 3 ],
																		   p [ 4 ],
																		   &sAddress,
																		   &seqNum,
																		   &sRequest );
		}
		break;
#endif
#ifdef CLD_SCENES_CMD_ENHANCED_VIEW_SCENE
		case (ZBHCI_MSG_VIEW_ENHANCED_SCENE):
		{
			tsCLD_ScenesEnhancedViewSceneRequestPayload    sRequest;

			sRequest.u16GroupId =  ZNC_RTN_U16 ( p, 5 );
			sRequest.u8SceneId  =  p[7];

			st    =  eCLD_ScenesCommandEnhancedViewSceneRequestSend ( p [ 3 ],
																		   p [ 4 ],
																		   &sAddress,
																		   &seqNum,
																		   &sRequest );
		}
		break;
#endif
#ifdef CLD_SCENES_CMD_COPY_SCENE
		case (ZBHCI_MSG_COPY_SCENE):
		{
			tsCLD_ScenesCopySceneRequestPayload    sRequest;

			sRequest.u8Mode         =  p[5];
			sRequest.u16FromGroupId =  ZNC_RTN_U16 ( p, 6 );
			sRequest.u8FromSceneId  =  p[8];
			sRequest.u16ToGroupId   =  ZNC_RTN_U16 ( p, 9 );
			sRequest.u8ToSceneId    =  p[11];

			st    =  eCLD_ScenesCommandCopySceneSceneRequestSend ( p [ 3 ],
																		 p [ 4 ],
																		 &sAddress,
																		 &seqNum,
																		 &sRequest );
		}
		break;
#endif
		case (ZBHCI_MSG_SCENE_MEMBERSHIP_REQUEST):
		{
			tsCLD_ScenesGetSceneMembershipRequestPayload    sRequest;

			sRequest.u16GroupId    =  ZNC_RTN_U16 ( p, 5 );
			st               =  eCLD_ScenesCommandGetSceneMembershipRequestSend ( p [ 3 ],
																						p [ 4 ],
																						&sAddress,
																						&seqNum,
																						&sRequest);
		}
		break;

		/* ON/OFF cluster commands */
		case (ZBHCI_MSG_ONOFF_EFFECTS):
		{

			tsCLD_OnOff_OffWithEffectRequestPayload    sRequest;

			sRequest.u8EffectId          =  p[5];
			sRequest.u8EffectVariant     =  p[6];
			st                     =  eCLD_OnOffCommandOffWithEffectSend ( p [ 3 ],
																				 p [ 4 ],
																				 &sAddress,
																				 &seqNum,
																				 &sRequest );
		}
		break;



		case (ZBHCI_MSG_ONOFF_TIMED):
		{

			tsCLD_OnOff_OnWithTimedOffRequestPayload    sRequest;

			sRequest.u8OnOff      =  p[5];
			sRequest.u16OnTime    =  ZNC_RTN_U16 ( p, 6 );
			sRequest.u16OffTime   =  ZNC_RTN_U16 ( p, 8 );

			st    =  eCLD_OnOffCommandOnWithTimedOffSend ( p [ 3 ],
																 p [ 4 ],
																 &sAddress,
																 &seqNum,
																 &sRequest );
		}
		break;

	 /* colour cluster commands */

		case (ZBHCI_MSG_MOVE_HUE):
		{
			tsCLD_ColourControl_MoveHueCommandPayload    sPayload;

			sPayload.eMode     =  p[5];
			sPayload.u8Rate    =  p[6];

			st    =  eCLD_ColourControlCommandMoveHueCommandSend ( p [ 3 ],
																		 p [ 4 ],
																		 &sAddress,
																		 &seqNum,
																		 &sPayload );

		}
		break;

		case (ZBHCI_MSG_MOVE_TO_HUE_SATURATION):
		{
			tsCLD_ColourControl_MoveToHueAndSaturationCommandPayload    sPayload;

			sPayload.u8Saturation         =  p[6];
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 7 );
			sPayload.u8Hue                =  p[5];

			st    =  eCLD_ColourControlCommandMoveToHueAndSaturationCommandSend ( p [ 3 ],
																						p [ 4 ],
																						&sAddress,
																						&seqNum,
																						&sPayload );

		}
		break;

		case (ZBHCI_MSG_MOVE_TO_HUE):
		{
			tsCLD_ColourControl_MoveToHueCommandPayload    sPayload;

			sPayload.eDirection           =  p[6];
			sPayload.u8Hue                =  p[5];
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 7 );

			st    =  eCLD_ColourControlCommandMoveToHueCommandSend ( p [ 3 ],
																		   p [ 4 ],
																		   &sAddress,
																		   &seqNum,
																		   &sPayload );

		}
		break;

		case (ZBHCI_MSG_STEP_HUE):
		{
			tsCLD_ColourControl_StepHueCommandPayload    sPayload;

			sPayload.eMode           =  p[5];
			sPayload.u8StepSize      =  p[6];
			sPayload.u8TransitionTime    =  p[7];

			st     =  eCLD_ColourControlCommandStepHueCommandSend ( p [ 3 ],
																		  p [ 4 ],
																		  &sAddress,
																		  &seqNum,
																		  &sPayload );

		}
		break;

		case (ZBHCI_MSG_MOVE_TO_SATURATION):
		{
			tsCLD_ColourControl_MoveToSaturationCommandPayload    sPayload;

			sPayload.u8Saturation         = p[5];
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 6 );

			st    =  eCLD_ColourControlCommandMoveToSaturationCommandSend ( p [ 3 ],
																				  p [ 4 ],
																				  &sAddress,
																				  &seqNum,
																				  &sPayload );

		}
		break;

		case (ZBHCI_MSG_MOVE_SATURATION):
		{
			tsCLD_ColourControl_MoveSaturationCommandPayload    sPayload;

			sPayload.eMode    =  p[5];
			sPayload.u8Rate   =  p[6];

			 st    =  eCLD_ColourControlCommandMoveSaturationCommandSend ( p [ 3 ],
																				 p [ 4 ],
																				 &sAddress,
																				 &seqNum,
																				 &sPayload );

		}
		break;

		case (ZBHCI_MSG_STEP_SATURATION):
		{
			tsCLD_ColourControl_StepSaturationCommandPayload    sPayload;

			sPayload.eMode               =  p[5];
			sPayload.u8StepSize          =  p[6];
			sPayload.u8TransitionTime    =  p[7];

			st    =  eCLD_ColourControlCommandStepSaturationCommandSend ( p [ 3 ],
																				p [ 4 ],
																				&sAddress,
																				&seqNum,
																				&sPayload );

		}
		break;

		case (ZBHCI_MSG_MOVE_TO_COLOUR):
		{
			tsCLD_ColourControl_MoveToColourCommandPayload    sPayload;

			sPayload.u16ColourX           =  ZNC_RTN_U16 ( p, 5 );
			sPayload.u16ColourY           =  ZNC_RTN_U16 ( p, 7 );
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 9 );


			st    =  eCLD_ColourControlCommandMoveToColourCommandSend ( p [ 3 ],
																			  p [ 4 ],
																			  &sAddress,
																			  &seqNum,
																			  &sPayload );

		}
		break;

		case (ZBHCI_MSG_MOVE_COLOUR):
		{
			tsCLD_ColourControl_MoveColourCommandPayload    sPayload;

			sPayload.i16RateX    =  ZNC_RTN_U16 ( p, 5 );
			sPayload.i16RateY    =  ZNC_RTN_U16 ( p, 7 ) ;

			st    =  eCLD_ColourControlCommandMoveColourCommandSend ( p [ 3 ],
																			p [ 4 ],
																			&sAddress,
																			&seqNum,
																			&sPayload );

		}
		break;

		case (ZBHCI_MSG_STEP_COLOUR):
		{
			tsCLD_ColourControl_StepColourCommandPayload    sPayload;

			sPayload.i16StepX             =  ZNC_RTN_U16 ( p, 5 );
			sPayload.i16StepY             =  ZNC_RTN_U16 ( p, 7 );
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 9 );

			st = eCLD_ColourControlCommandStepColourCommandSend ( p [ 3 ],
																		p [ 4 ],
																		&sAddress,
																		&seqNum,
																		&sPayload );

		}
		break;

		case (ZBHCI_MSG_COLOUR_LOOP_SET):
		{
			tsCLD_ColourControl_ColourLoopSetCommandPayload    sPayload;
			sPayload.u8UpdateFlags    =  p [ 5 ];
			sPayload.eAction      =  p [ 6 ];
			sPayload.eDirection       =  p [ 7 ];
			sPayload.u16Time      =  ZNC_RTN_U16 ( p, 8 );
			sPayload.u16StartHue      =  ZNC_RTN_U16 ( p, 10 );

			st = eCLD_ColourControlCommandColourLoopSetCommandSend ( p [ 3 ],
																		   p [ 4 ],
																		   &sAddress,
																		   &seqNum,
																		   &sPayload );
		}
		break;

		case (ZBHCI_MSG_MOVE_TO_COLOUR_TEMPERATURE):
		{
			tsCLD_ColourControl_MoveToColourTemperatureCommandPayload    sPayload;

			sPayload.u16ColourTemperatureMired    =  ZNC_RTN_U16 ( p, 5 );
			sPayload.u16TransitionTime            =  ZNC_RTN_U16 ( p, 7 );
			st    =  eCLD_ColourControlCommandMoveToColourTemperatureCommandSend ( p [ 3 ],
																						 p [ 4 ],
																						 &sAddress,
																						 &seqNum,
																						 &sPayload );
		}
		break;

		case (ZBHCI_MSG_MOVE_COLOUR_TEMPERATURE):
		{
			tsCLD_ColourControl_MoveColourTemperatureCommandPayload    sPayload;

			sPayload.eMode                           =  p[5];
			sPayload.u16Rate                         =  ZNC_RTN_U16 ( p, 6 );
			sPayload.u16ColourTemperatureMiredMin    =  ZNC_RTN_U16 ( p, 8 );
			sPayload.u16ColourTemperatureMiredMax    =  ZNC_RTN_U16 ( p, 10);

			st    =  eCLD_ColourControlCommandMoveColourTemperatureCommandSend ( p [ 3 ],
																					   p [ 4 ],
																					   &sAddress,
																					   &seqNum,
																					   &sPayload );
		}
		break;

		case (ZBHCI_MSG_STEP_COLOUR_TEMPERATURE):
		{
			tsCLD_ColourControl_StepColourTemperatureCommandPayload    sPayload;

			sPayload.eMode                           =  p[5];
			sPayload.u16StepSize                     =  ZNC_RTN_U16 ( p, 6 );
			sPayload.u16ColourTemperatureMiredMin    =  ZNC_RTN_U16 ( p, 8 );
			sPayload.u16ColourTemperatureMiredMax    =  ZNC_RTN_U16 ( p, 10);
			sPayload.u16TransitionTime               =  ZNC_RTN_U16 ( p, 12);
			sPayload.u8OptionsMask                   =  ZNC_RTN_U16 ( p, 14);
			sPayload.u8OptionsOverride               =  ZNC_RTN_U16 ( p, 15);

			st    =  eCLD_ColourControlCommandStepColourTemperatureCommandSend ( p [ 3 ],
																					   p [ 4 ],
																					   &sAddress,
																					   &seqNum,
																					   &sPayload );
		}
		break;


		case (ZBHCI_MSG_ENHANCED_MOVE_TO_HUE):
		{
			tsCLD_ColourControl_EnhancedMoveToHueCommandPayload    sPayload;

			sPayload.eDirection           =  p[5];
			sPayload.u16EnhancedHue       =  ZNC_RTN_U16 ( p, 6 );
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 8 );

			st    =  eCLD_ColourControlCommandEnhancedMoveToHueCommandSend ( p [ 3 ],
																				   p [ 4 ],
																				   &sAddress,
																				   &seqNum,
																				   &sPayload );
		}
		break;

		case (ZBHCI_MSG_ENHANCED_MOVE_HUE):
		{
			tsCLD_ColourControl_EnhancedMoveHueCommandPayload    sPayload;

			sPayload.eMode      =  p[5];
			sPayload.u16Rate    =  ZNC_RTN_U16 ( p, 6 );

			st    =  eCLD_ColourControlCommandEnhancedMoveHueCommandSend ( p [ 3 ],
																				 p [ 4 ],
																				 &sAddress,
																				 &seqNum,
																				 &sPayload );
		}
		break;

		case (ZBHCI_MSG_ENHANCED_STEP_HUE):
		{
			tsCLD_ColourControl_EnhancedStepHueCommandPayload    sPayload;

			sPayload.eMode                = p[5];
			sPayload.u16StepSize          =  ZNC_RTN_U16 ( p, 6 );
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 8 );

			st    =  eCLD_ColourControlCommandEnhancedStepHueCommandSend ( p [ 3 ],
																				 p [ 4 ],
																				 &sAddress,
																				 &seqNum,
																				 &sPayload );
		}
		break;



		case (ZBHCI_MSG_ENHANCED_MOVE_TO_HUE_SATURATION):
		{
			tsCLD_ColourControl_EnhancedMoveToHueAndSaturationCommandPayload    sPayload;

			sPayload.u8Saturation         =  p[5];
			sPayload.u16EnhancedHue       =  ZNC_RTN_U16 ( p, 6 );
			sPayload.u16TransitionTime    =  ZNC_RTN_U16 ( p, 8 );

			st    =  eCLD_ColourControlCommandEnhancedMoveToHueAndSaturationCommandSend ( p [ 3 ],
																								p [ 4 ],
																								&sAddress,
																								&seqNum,
																								&sPayload );
		}
		break;


		case (ZBHCI_MSG_STOP_MOVE_STEP):
		{
			tsCLD_ColourControl_StopMoveStepCommandPayload    sPayload;

			sPayload.u8OptionsMask        =  p [ 5 ];
			sPayload.u8OptionsOverride    =  p [ 6 ];
			st    =  eCLD_ColourControlCommandStopMoveStepCommandSend ( p [ 3 ],
																			  p [ 4 ],
																			  &sAddress,
																			  &seqNum,
																			  &sPayload );
		}
		break;



		/* Identify commands*/

		case (ZBHCI_MSG_IDENTIFY_SEND):
		{
			tsCLD_Identify_IdentifyRequestPayload    sCommand;

			sCommand.u16IdentifyTime    =  ZNC_RTN_U16 ( p, 5 );
			st    =  eCLD_IdentifyCommandIdentifyRequestSend ( p [ 3 ],
																	 p [ 4 ],
																	 &sAddress,
																	 &seqNum,
																	 &sCommand );
		}
		break;

		case (ZBHCI_MSG_IDENTIFY_QUERY):
		{

			st    =  eCLD_IdentifyCommandIdentifyQueryRequestSend ( p [ 3 ],
																		  p [ 4 ],
																		  &sAddress,
																		  &seqNum );
		}
		break;

#ifdef  CLD_IDENTIFY_SUPPORT_ZLL_ENHANCED_COMMANDS
		case (ZBHCI_MSG_IDENTIFY_TRIGGER_EFFECT):
		{
			st = eCLD_IdentifyCommandTriggerEffectSend ( p [ 3 ],
															   p [ 4 ],
															   &sAddress,
															   &seqNum,
															   p [ 5 ],
															   p [ 6 ]);
		}
		break;
#endif
		/* profile agnostic commands */
		case (ZBHCI_MSG_READ_ATTRIBUTE_REQUEST):
		{
			u16    au16AttributeList[10];
			u16    u16ClusterId;
			u16    u16ManId;
			u8     i = 0;


			u16ClusterId    =  ZNC_RTN_U16 (p, 5 );
			u16ManId    =  ZNC_RTN_U16 (p, 9 );

			while ( ( i < 10 ) &&
					( i < p[11] )
				  )
			{
				au16AttributeList [ i ]    =  ZNC_RTN_U16 ( p , ( 12 + (i * 2) ) );
				i++;
			}

			st    =  eZCL_SendReadAttributesRequest ( p [ 3 ],
															p [ 4 ],
															u16ClusterId,
															p [ 7 ],
															&sAddress,
															&seqNum,
															p [ 11 ],
															p [ 8 ],
															u16ManId,
															au16AttributeList );
		}
		break;

		case (ZBHCI_MSG_WRITE_ATTRIBUTE_REQUEST):
		{
			u16    u16ClusterId;
			u16    u16ManId;
			u16    u16SizePayload;

			u16ClusterId      =  ZNC_RTN_U16 ( p, 5 );
			u16ManId          =  ZNC_RTN_U16 ( p, 9 );

			/* payload - sum of add mode , short addr, cluster id, manf id, manf specific flag */
			/* src ep,  dest ep, num attrib , direction*/
			u16SizePayload    =  u16PacketLength - ( 12 ) ;
			st          =  APP_eSendWriteAttributesRequest ( p [ 3 ],
																   p [ 4 ],
																   u16ClusterId,
																   p [ 7 ],
																   &sAddress,
																   &seqNum,
																   p [ 8 ],
																   u16ManId,
																   &p [ 12 ],
																   p [ 11 ],
																   u16SizePayload );
		}
		break;


		case ZBHCI_MSG_CONFIG_REPORTING_REQUEST:
		{
			u16                                         u16ClusterId;
			u16                                         u16ManId;
			tsZCL_AttributeReportingConfigurationRecord    asAttribReportConfigRecord[10];
			int                                            i;
			u8                                          u8Offset = 12;

			u16ClusterId      =  ZNC_RTN_U16 ( p, 5 );
			u16ManId          =  ZNC_RTN_U16 ( p, 9 );


			for (i = 0; i < p[11]; i++)
			{
				if (i < 10)
				{
				/* Destination structure is not packed so we have to manually load rather than just copy */
					asAttribReportConfigRecord [ i ].u8DirectionIsReceived          =  p [ u8Offset++ ];
					asAttribReportConfigRecord [ i ].eAttributeDataType             =  p [ u8Offset++ ];
					asAttribReportConfigRecord [ i ].u16AttributeEnum               =  ZNC_RTN_U16_OFFSET ( p,
																										u8Offset,
																										u8Offset );
					asAttribReportConfigRecord [ i ].u16MinimumReportingInterval    =  ZNC_RTN_U16_OFFSET ( p,
																										u8Offset,
																										u8Offset );
					asAttribReportConfigRecord [ i ].u16MaximumReportingInterval    =  ZNC_RTN_U16_OFFSET ( p,
																										u8Offset,
																										u8Offset );
					asAttribReportConfigRecord [ i ].u16TimeoutPeriodField          =  ZNC_RTN_U16_OFFSET ( p,
																										u8Offset,
																										u8Offset );
					asAttribReportConfigRecord[i].uAttributeReportableChange.zuint8ReportableChange = p [u8Offset++ ];
				}
			}

			st =  eZCL_SendConfigureReportingCommand(p [ 3 ],           // u8SourceEndPointId
														   p [ 4 ],           // u8DestinationEndPointId
														   u16ClusterId,                    // u16ClusterId
														   p [ 7 ],           // bDirectionIsServerToClient
														   &sAddress,                       // *psDestinationAddress
														   &seqNum,                       // *pu8TransactionSequenceNumber
														   p [ 11 ],          // u8NumberOfAttributesInRequest
														   p [ 8 ],           // bIsManufacturerSpecific
														   u16ManId,                        // u16ManufacturerCode
														   asAttribReportConfigRecord );    // *psAttributeReportingConfigurationRecord
		}
		break;

		case ZBHCI_MSG_ATTRIBUTE_DISCOVERY_REQUEST:
		case ZBHCI_MSG_ATTRIBUTE_EXT_DISCOVERY_REQUEST:
		{
			bool_t     bIsExtReq = FALSE;
			u16     u16ClusterId;
			u16     u16AttributeId;
			u16     u16ManufacturerCode;

			if (ZBHCI_MSG_ATTRIBUTE_EXT_DISCOVERY_REQUEST == u16PacketType)
			{
				bIsExtReq = TRUE;
			}

			u16ClusterId       =  ZNC_RTN_U16 ( p, 5 );
			u16AttributeId     =  ZNC_RTN_U16 ( p, 7 );
			u16ManufacturerCode    =  ZNC_RTN_U16 ( p, 11 );

			st = APP_eZclDiscoverAttributes(bIsExtReq,
												  p[3],      // u8SourceEndPointId
												  p[4],      // u8DestinationEndPointId
												  u16ClusterId,            // u16ClusterId
												  p[9],      // bDirectionIsServerToClient
												  &sAddress,               // *psDestinationAddress
												  &seqNum,               // *pu8TransactionSequenceNumber
												  u16AttributeId,          // u16AttributeId
												  p[10],     // bIsManufacturerSpecific
												  u16ManufacturerCode,     // u16ManufacturerCode
												  p[13]);    // u8MaximumNumberOfIdentifiers
		}
		break;

		case ZBHCI_MSG_COMMAND_GENERATED_DISCOVERY_REQUEST:
		{
			u16    u16ClusterId;
			u16    u16ManufacturerCode;

			u16ClusterId       =  ZNC_RTN_U16 ( p, 5 );
			u16ManufacturerCode    =  ZNC_RTN_U16 ( p, 10 );

			st = APP_eZclDiscoverCommandGenerated ( p [ 3 ],      // u8SourceEndPointId
														  p [ 4 ],      // u8DestinationEndPointId
														  u16ClusterId,               // u16ClusterId
														  p [ 7 ],      // bDirectionIsServerToClient
														  &sAddress,                  // *psDestinationAddress
														  &seqNum,                  // *pu8TransactionSequenceNumber
														  p [ 8 ],      // u8CommandId
														  p [ 9 ],      // bIsManufacturerSpecific
														  u16ManufacturerCode,        // u16ManufacturerCode
														  p [ 12 ] );   // u8MaximumNumberOfCommands
		}
		break;

		case ZBHCI_MSG_COMMAND_RECEIVED_DISCOVERY_REQUEST:
		{
			u16    u16ClusterId;
			u16    u16ManufacturerCode;

			u16ClusterId           =  ZNC_RTN_U16 ( p, 5 );
			u16ManufacturerCode    =  ZNC_RTN_U16 ( p, 10 );

			st = APP_eZclDiscoverCommandReceived ( p [ 3 ],     // u8SourceEndPointId
														 p [ 4 ],     // u8DestinationEndPointId
														 u16ClusterId,              // u16ClusterId
														 p [ 7 ],     // bDirectionIsServerToClient
														 &sAddress,                 // *psDestinationAddress
														 &seqNum,                 // *pu8TransactionSequenceNumber
														 p [ 8 ],     // u8CommandId
														 p [ 9 ],     // bIsManufacturerSpecific
														 u16ManufacturerCode,       // u16ManufacturerCode
														 p [ 12 ] );  // u8MaximumNumberOfCommands
		}
		break;
		case ZBHCI_MSG_READ_REPORT_CONFIG_REQUEST:
		{
			u8                                               i;
			u8                                               u8NumberOfAttributesInRequest;
			u16                                              u16ClusterId;
			u16                                              u16ManufacturerCode;
			tsZCL_AttributeReadReportingConfigurationRecord     asAttributeReadReportingConfigurationRecord[8];
			u8                                               u8BufferOffset = 12;

			u8NumberOfAttributesInRequest    =  p[8];
			u16ClusterId                     =  ZNC_RTN_U16 ( p, 5  );
			u16ManufacturerCode              =  ZNC_RTN_U16 ( p, 10 );


			for (i = 0; i < u8NumberOfAttributesInRequest; i++)
			{
				asAttributeReadReportingConfigurationRecord[i].u8DirectionIsReceived     =  p[u8BufferOffset++];
				asAttributeReadReportingConfigurationRecord[i].u16AttributeEnum          =  ZNC_RTN_U16_OFFSET ( p,
																											 u8BufferOffset,
																											 u8BufferOffset);
			}

			st    =  eZCL_SendReadReportingConfigurationCommand ( p [ 3 ],                                //  u8SourceEndPointId,
																		p [ 4 ],                                //  u8DestinationEndPointId,
																		u16ClusterId,                                         //  u16ClusterId,
																		p [ 7 ],                                //  bDirectionIsServerToClient,
																		&sAddress,                                            // *psDestinationAddress,
																		&seqNum,                                            // *pu8TransactionSequenceNumber,
																		u8NumberOfAttributesInRequest,                        //  u8NumberOfAttributesInRequest,
																		p [ 9 ],                                //  bIsManufacturerSpecific,
																		u16ManufacturerCode,                                  //  u16ManufacturerCode,
																		&asAttributeReadReportingConfigurationRecord[0] );    //  *psAttributeReadReportingConfigurationRecord);
		}
		break;

		case ZBHCI_MSG_SEND_IAS_ZONE_ENROLL_RSP:
		{
			tsCLD_IASZone_EnrollResponsePayload    sEnrollResponsePayload;

			sEnrollResponsePayload.e8EnrollResponseCode    =  p[5];
			sEnrollResponsePayload.u8ZoneID                =  p[6];

			st    = eCLD_IASZoneEnrollRespSend ( p [ 3 ],         // u8SourceEndPointId,
													   p [ 4 ],         // u8DestinationEndPointId,
													   &sAddress,                     // *psDestinationAddress,
													   &seqNum,                     // *pu8TransactionSequenceNumber,
													   &sEnrollResponsePayload );     // *psPayload);
		}
		break;

#ifdef CLD_DOOR_LOCK
		case (ZBHCI_MSG_LOCK_UNLOCK_DOOR):
		{
			st     =  eCLD_DoorLockCommandLockUnlockRequestSend ( p [ 3 ],
																		p [ 4 ],
																		&sAddress,
																		&seqNum,
																		p [ 5 ] );
		}
		break;
#endif

#ifdef CLD_ASC_LOG
		case ZBHCI_MSG_ASC_LOG_MSG:
		{
			tsCLD_ASC_LogNotificationORLogResponsePayload    sNotificationPayload;

			sNotificationPayload.utctTime              =  ZNC_RTN_U32 ( p, 5 );
			sNotificationPayload.u32LogId              =  ZNC_RTN_U32 ( p, 9 );
			sNotificationPayload.u32LogLength          =  ZNC_RTN_U32 ( p, 13);
			sNotificationPayload.pu8LogData            =  &p[17];
			st =  eCLD_ASCLogNotificationSend ( p [ 3 ],     // u8SourceEndPointId,
													  p [ 4 ],     // u8DestinationEndPointId,
													  &sAddress,                 // *psDestinationAddress,
													  &seqNum,                 // *pu8TransactionSequenceNumber,
													  &sNotificationPayload);    // *psPayload);)
		}
		break;
#endif

#ifdef NETWORK_RECOVERY
		case (ZBHCI_MSG_NWK_RECOVERY_EXTRACT_REQ):
		{
			tsNwkRecovery    sNwkRecovery = { { 0 } };
			vNetworkRecoveryObtainRecoverData ( &sNwkRecovery );
			zbhciTx( ZBHCI_MSG_NWK_RECOVERY_EXTRACT_RSP,
							  sizeof(sNwkRecovery),
							  (u8 *)&sNwkRecovery );
		}
		break;

		case (ZBHCI_MSG_NWK_RECOVERY_RESTORE_REQ):
		{
			u8 u8Success = 0;
			vNetworkRecoveryInsertRecoverData( ( tsNwkRecovery * ) &p );
			zbhciTx( ZBHCI_MSG_NWK_RECOVERY_RESTORE_RSP,
							  sizeof(u8),
							  &u8Success );
		}
		break;
#endif
		case ZBHCI_MSG_BASIC_RESET_TO_FACTORY_DEFAULTS:
		{
			st    =  APP_eZclBasicResetToFactoryDefaults( p[3],      //  u8SourceEndPointId
																p[4],      //  u8DestinationEndPointId
																&sAddress,               // *psDestinationAddress,
																&seqNum );             // *pu8TransactionSequenceNumber
		}
		break;

#ifdef CLD_OTA


		case ZBHCI_MSG_UPGRADE_END_RESPONSE:
		{
			u8                              u8SrcEndPoint;
			u8                              u8DstEndPoint;
			tsOTA_UpgradeEndResponsePayload    sUpgradeResponsePayload;

			u8SrcEndPoint                  =  p[3];
			u8DstEndPoint                  =  p[4];
			sUpgradeResponsePayload.u32UpgradeTime         =  ZNC_RTN_U32 ( p,  6  );
			sUpgradeResponsePayload.u32CurrentTime         =  ZNC_RTN_U32 ( p,  10 );
			sUpgradeResponsePayload.u32FileVersion         =  ZNC_RTN_U32 ( p,  14 );
			sUpgradeResponsePayload.u16ImageType           =  ZNC_RTN_U16 ( p,  18 );
			sUpgradeResponsePayload.u16ManufacturerCode    =  ZNC_RTN_U16 ( p,  20 );

			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nZBHCI_MSG_UPGRADE_END_RESPONSE");
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nAddr Mode: %x", sAddress.eAddressMode);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nAddr: %x", sAddress.uAddress.u16DestinationAddress);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nSrcEndPoint: %x", u8SrcEndPoint);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nDstEndPoint: %x", u8DstEndPoint);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nUpgradeTime: %x", sUpgradeResponsePayload.u32UpgradeTime);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nCurrentTime: %x", sUpgradeResponsePayload.u32CurrentTime);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nFileVersion: %x", sUpgradeResponsePayload.u32FileVersion);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nImageType: %x", sUpgradeResponsePayload.u16ImageType);
			vLog_Printf (TRACE_APP, LOG_DEBUG, "\nManufacturerCode: %x", sUpgradeResponsePayload.u16ManufacturerCode);

			st    = eOTA_ServerUpgradeEndResponse(u8SrcEndPoint,                //  u8SourceEndpoint
														u8DstEndPoint,                //  u8DestinationEndpoint
														&sAddress,                    // *psDestinationAddress,
														&sUpgradeResponsePayload,     // *psUpgradeResponsePayload,
														p[5]);          // u8 u8TransactionSequenceNumber);
		}
		break;

		case ZBHCI_MSG_SEND_WAIT_FOR_DATA_PARAMS:
		{
			vLog_Printf(TRACE_APP, LOG_DEBUG, "\nZBHCI_MSG_SEND_WAIT_FOR_DATA_PARAMS");

			u8                              u8SrcEndPoint;
				u8                              u8DstEndPoint;
				tsOTA_ImageBlockResponsePayload    sImageBlockResponsePayload;

				u8SrcEndPoint                                                           =  p[3];
				u8DstEndPoint                                                           =  p[4];
				sImageBlockResponsePayload.st                                     =  p[6];

				sImageBlockResponsePayload.uMessage.sWaitForData.u32CurrentTime         =  ZNC_RTN_U32 ( p, 7  );
				sImageBlockResponsePayload.uMessage.sWaitForData.u32RequestTime         =  ZNC_RTN_U32 ( p, 11  );
				sImageBlockResponsePayload.uMessage.sWaitForData.u16BlockRequestDelayMs =  ZNC_RTN_U16 ( p, 15  );

				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nAddr Mode: %x", sAddress.eAddressMode);
				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nAddr: %x", sAddress.uAddress.u16DestinationAddress);
				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nSrcEndPoint: %x", u8SrcEndPoint);
				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nDstEndPoint: %x", u8DstEndPoint);
				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nStatus: %x", sImageBlockResponsePayload.st);
				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nCurrentTime: %x", sImageBlockResponsePayload.uMessage.sWaitForData.u32CurrentTime);
				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nRequestTime: %x", sImageBlockResponsePayload.uMessage.sWaitForData.u32RequestTime);
				vLog_Printf(TRACE_APP, LOG_DEBUG, "\nBlockDelay: %x", sImageBlockResponsePayload.uMessage.sWaitForData.u16BlockRequestDelayMs);

				st = eOTA_ServerImageBlockResponse( u8SrcEndPoint,                    /* u8SourceEndpoint */
														  u8DstEndPoint,                    /*  u8DestinationEndpoint */
														  &sAddress,                        /*  *psDestinationAddress */
														  &sImageBlockResponsePayload,      /* *psImageBlockResponsePayload */
														  0,                                /*  u8BlockSize           */
														  p[5]);              /*  u8TransactionSequenceNumb */
			}
			break;


#endif
#endif
		default:
				st = ZBHCI_MSG_STATUS_UNHANDLED_COMMAND;
			break;
		}
	ret[0] = st;
	ret[1] =  seqNum;
	COPY_U16TOBUFFER_BE(ret+2,msgType);
	zbhciTx ( ZBHCI_MSG_STATUS,
					   4,
					   ret );
}
