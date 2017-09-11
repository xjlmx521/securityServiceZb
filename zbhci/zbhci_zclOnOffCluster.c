#include "../../proj/tl_common.h"
#include "../include/zb_common.h"
#include "../../zigbee/zcl/zcl_include.h"
#include "zbhci.h"
//void zcl_onOff_cluster_on_cmd(u8 *p)
//{
//	u8 *ptr = p;
//	epInfo_t dstEpInfo;
//	u8 srcEp = *ptr;
//
//	ptr = ptr + sizeof(u8);
//	dstEpInfo.dstAddrMode = *ptr;
//	ptr = ptr + sizeof(u8);
//	dstEpInfo.dstEp = *ptr;
//	ptr = ptr + sizeof(u8);
//	if(dstEpInfo.dstAddrMode != 0x02 && dstEpInfo.dstAddrMode != 0x01){
//		return;
//	}
//	memcpy((u8 *)&dstEpInfo.dstAddr.shortAddr, ptr, sizeof(u16));
//	ptr = ptr + sizeof(u16);
//	memcpy((u8 *)&dstEpInfo.profileId, ptr, sizeof(u16));
//	ptr = ptr + sizeof(u16);
//	dstEpInfo.txOptions = *ptr;
//	ptr = ptr + sizeof(u8);
//	dstEpInfo.radius = *ptr;
//	ptr = ptr + sizeof(u8);
//
//	//zcl_onOff_on(srcEp, &dstEpInfo, FALSE, testSeqNum++);
//	zcl_onOff_onCmd(srcEp, &dstEpInfo, FALSE);
//}
//
//void zcl_onOff_cluster_off_cmd(u8 *p)
//{
//	u8 *ptr = p;
//	epInfo_t dstEpInfo;
//	u8 srcEp = *ptr;
//
//	ptr = ptr + sizeof(u8);
//	dstEpInfo.dstAddrMode = *ptr;
//	ptr = ptr + sizeof(u8);
//	dstEpInfo.dstEp = *ptr;
//	ptr = ptr + sizeof(u8);
//	if(dstEpInfo.dstAddrMode != 0x02 && dstEpInfo.dstAddrMode != 0x01){
//		return;
//	}
//	memcpy((u8 *)&dstEpInfo.dstAddr.shortAddr, ptr, sizeof(u16));
//	ptr = ptr + sizeof(u16);
//	memcpy((u8 *)&dstEpInfo.profileId, ptr, sizeof(u16));
//	ptr = ptr + sizeof(u16);
//	dstEpInfo.txOptions = *ptr;
//	ptr = ptr + sizeof(u8);
//	dstEpInfo.radius = *ptr;
//	ptr = ptr + sizeof(u8);
//
//	//zcl_onOff_off(srcEp, &dstEpInfo, FALSE, testSeqNum++);
//	zcl_onOff_offCmd(srcEp, &dstEpInfo, FALSE);
//}



u8 zbhci_zclOnoffCmdHandle(u8 *p, u8 *seqNum)
{
	u8 *ptr = p;
	epInfo_t dstEpInfo;
	u8 srcEp;
	zbhciTxClusterCmdAddrResolve(&dstEpInfo,&srcEp,&ptr);
	if(dstEpInfo.dstAddrMode == ZBHCI_ADDRMODE_NOTX){
		return RET_ERROR;
	}
	u8 cmd = *ptr;
	*seqNum = ZCL_SEQ_NUM;
	zcl_sendCmd(srcEp, &dstEpInfo, ZCL_CLUSTER_GEN_ON_OFF,cmd,TRUE,ZCL_FRAME_CLIENT_SERVER_DIR, TRUE,0,*seqNum, 0, NULL);
	return RET_OK;
}

u8 zbhci_zclLevelCtrlCmdHandle(u16 msgType, u8 *p, u8 *seqNum)
{
	u8 *ptr = p;
	epInfo_t dstEpInfo;
	u8 srcEp;
	zbhciTxClusterCmdAddrResolve(&dstEpInfo,&srcEp,&ptr);
	if(dstEpInfo.dstAddrMode == ZBHCI_ADDRMODE_NOTX){
		return RET_ERROR;
	}

	u8 cmdPayload[8];
	u8 plen = 0;
	u8 cmd;

	switch(msgType){
	case ZBHCI_MSG_MOVE_TO_LEVEL:
	{
		cmd = ZCL_CMD_LEVEL_MOVE_TO_LEVEL;
		cmdPayload[0] = *ptr++;//level
		cmdPayload[2] = *ptr++;//tx time h
		cmdPayload[1] = *ptr++;//tx time low
		plen = 3;

	}
	break;
	case ZBHCI_MSG_MOVE_TO_LEVEL_ONOFF:
	{
		u8 onoff = *ptr++;
		if(onoff){
			cmd = ZCL_CMD_LEVEL_MOVE_TO_LEVEL_WITH_ON_OFF;
		}else{
			cmd = ZCL_CMD_LEVEL_MOVE_TO_LEVEL;
		}
		cmdPayload[0] = *ptr++;//level
		cmdPayload[2] = *ptr++;//tx time h
		cmdPayload[1] = *ptr++;//tx time low
		plen = 3;
	}
	break;
	default:
	break;
	}

	*seqNum = ZCL_SEQ_NUM;
	zcl_sendCmd(srcEp, &dstEpInfo, ZCL_CLUSTER_GEN_LEVEL_CONTROL,cmd,TRUE,ZCL_FRAME_CLIENT_SERVER_DIR, TRUE,0,*seqNum, plen, cmdPayload);
	return RET_OK;
}
