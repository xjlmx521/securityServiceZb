#include "../../../proj/tl_common.h"
#include "../zbhci.h"


#if USE_NXP_SFTWARE
#define		USB_RX_BUFFER		2
#define		USB_RX_MAXLEN		256
u8 usbRxBuffer[USB_RX_BUFFER][USB_RX_MAXLEN];
u8 rcvLen = 0;
u8 rxPtr = 0;

zbhciRxCbFun hciCb = NULL;
zbhciTxDoneCbFun hciTxDoneCb = NULL;
static void usbNXP_rxCb(unsigned char *data){
	//SL_END_CHAR
	rcvLen++;
	if(*data != 0x03){
		USBCDC_RxBufSet(++data);
	}else{
		USBCDC_RxBufSet(usbRxBuffer[(rxPtr++&1)]);
		if(hciCb){
			hciCb(data - rcvLen + 1,rcvLen);
		}
		rcvLen = 0;//reset rcvLen
	}
}
bool usbRwBusy(void ){
	return (!USBCDC_IsAvailable());
}



zbhciTx_e usbRwTx(u8 *buf, u8 len){
	if(USBCDC_IsAvailable()){
		USBCDC_DataSend(buf, len);
		return ZBHCI_TX_SUCCESS;
	}
	return ZBHCI_TX_BUSY;
}


void USB_LogInit(void)
{
    write_reg8(0x80013c, 0x40);
    write_reg8(0x80013d, 0x09);
}


void usbRwInit(zbhciRxCbFun *cb, zbhciTxDoneCbFun *txDoneCb){
	USB_Init();
	USB_LogInit();
	usb_dp_pullup_en (1);
	USBCDC_RxBufSet(usbRxBuffer[(rxPtr++&0x03)]);
	USBCDC_CBSet(usbNXP_rxCb, txDoneCb);
	hciCb = cb;
	hciTxDoneCb = txDoneCb;
}

void usbRwTask(void ){
	USB_IrqHandle();
}
#else
//define rx buffer
#define RX_BUF_LEN    64 //in bytes
#define RX_BUF_NUM    4
static unsigned char rx_buf[RX_BUF_NUM][RX_BUF_LEN];
static unsigned char rx_ptr = 0;

u8 tx_rdPtr = 0;
zbhciRxCbFun hciCb = NULL;
zbhciTxDoneCbFun hciTxDoneCb = NULL;
static void USBCDC_RxCb(unsigned char *data){
    USBCDC_RxBufSet(rx_buf[(rx_ptr++&0x03)]);
    if(hciCb){
    	hciCb(data,RX_BUF_LEN);
    }
}



u8 push_data_flag = 0;
u8 checksum(u8 *data,u8 len){
	u8 ret = *data;
	for(u8 i=0;i<len - 1;i++){
		ret ^= data[i+1];
	}
	return ret;
}
bool usbRwBusy(void ){
	return (!USBCDC_IsAvailable());
}



zbhciTx_e usbRwTx(u8 *buf, u8 len){
	if(USBCDC_IsAvailable()){
		USBCDC_DataSend(buf, len);
		return ZBHCI_TX_SUCCESS;
	}
	return ZBHCI_TX_BUSY;
}


void USB_LogInit(void)
{
    write_reg8(0x80013c, 0x40);
    write_reg8(0x80013d, 0x09);
}


void usbRwInit(zbhciRxCbFun *cb, zbhciTxDoneCbFun *txDoneCb){
	USB_Init();
	USB_LogInit();
	usb_dp_pullup_en (1);
	USBCDC_RxBufSet(rx_buf[(rx_ptr++&0x03)]);
	USBCDC_CBSet(USBCDC_RxCb, txDoneCb);
	hciCb = cb;
	hciTxDoneCb = txDoneCb;
}

void usbRwTask(void ){
	USB_IrqHandle();
}
#endif


