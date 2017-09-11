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
#include "zbhci.h"

zbhciTx_e zbhciTx(u16 u16Type, u16 u16Length, u8 *pu8Data){
#if USB_CDCUSED
#if USE_NXP_SFTWARE
	return sl_txMsg(u16Type,u16Length,pu8Data);
#else
	return sl_usbTxMsg(u16Type,u16Length,pu8Data);
#endif
#elif UART_USED

#elif SPI_USED

#elif I2C_USED

#endif
}
#if USB_CDCUSED && !USE_NXP_SFTWARE
struct zbhci_waitMoreData_t{
	u8					rxData[256];
	ev_time_event_t		*wmTimer;
	u8					wptrIndx;
}zbhci;
#define		GET_RXPACKETLEN(ptr)			(((ptr)[2]<<8)|((ptr)[3]))
s32 zbhciPacketRxTimeoutCb(void *arg){
	zbhci.wmTimer = NULL;
	zbhci.wptrIndx = 0;
	return -1;
}

bool zbhciPacketRxCompleted(u8 **buf){
	u16 len = 0;
	if(!zbhci.wptrIndx){
		len = GET_RXPACKETLEN(*buf) + 5;
	}else{
		len = GET_RXPACKETLEN(zbhci.rxData) + 5;
	}

	if(len<64){
		return TRUE;
	}

	memcpy(zbhci.rxData + zbhci.wptrIndx,*buf,64);
	zbhci.wptrIndx += 64;

	if(zbhci.wptrIndx >= len){
		*buf = zbhci.rxData;
		zbhci.wptrIndx = 0;
		TL_ZB_TIMER_CANCEL(&zbhci.wmTimer);
		return TRUE;
	}
	if(!zbhci.wmTimer){
		zbhci.wmTimer = TL_ZB_TIMER_SCHEDULE(zbhciPacketRxTimeoutCb,NULL,30*1000);
	}
	return FALSE;
}
#endif


void zbhciRxCb(u8 *buf,u8 len){
#if USE_NXP_SFTWARE
	sl_convertRxMessage(buf,len);
#elif USB_CDCUSED
	if(zbhciPacketRxCompleted(&buf)!=TRUE){
		return;
	}
#endif
	zbhci_msg_t *msg = (zbhci_msg_t *)buf;
	u16 pLen = (msg->msgLen16H<<8) + msg->msgLen16L;
	u16 msgType = (msg->msgType16H<<8) + msg->msgType16L;
	zbhciProcessIncommingSerialCmd(msgType,pLen,msg->pData);
}

void zbhciTxDoneCb(u8 *buf){

}

void zbhciInit(void ){

#if USB_CDCUSED
	usbRwInit(zbhciRxCb,zbhciTxDoneCb);
#elif UART_USED

#elif SPI_USED

#elif I2C_USED

#endif

}

void zbhciTask(){
#if USB_CDCUSED
	//Do CDC task
	usbRwTask();
#elif UART_USED

#elif SPI_USED

#elif I2C_USED

#endif
}

