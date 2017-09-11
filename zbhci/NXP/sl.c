/****************************************************************************
 *
 * MODULE:             ZigbeeNodeControlBridge
 *
 * COMPONENT:          Serial Link to Host
 *
 * VERSION:
 *
 * REVISION:           $$
 *
 * DATED:              $$
 *
 * STATUS:             $State: Exp $
 *
 * AUTHOR:             Lee Mitchell
 *
 * DESCRIPTION:
 *
 *
 * LAST MODIFIED BY:   $Author: nxp29741 $
 *                     $Modtime: $
 *
 ****************************************************************************
 *
 * This software is owned by NXP B.V. and/or its supplier and is protected
 * under applicable copyright laws. All rights are reserved. We grant You,
 * and any third parties, a license to use this software solely and
 * exclusively on NXP products [NXP Microcontrollers such as JN5168, JN5179].
 * You, and any third parties must reproduce the copyright and warranty notice
 * and any other legend of ownership on each copy or partial copy of the
 * software.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Copyright NXP B.V. 2016. All rights reserved
 *
 ****************************************************************************/
#include "SerialLink.h"
#include "../zbhci.h"
#ifdef DEBUG_SERIAL_LINK
#define DEBUG_SL            TRUE
#else
#define DEBUG_SL            FALSE
#endif

/****************************************************************************/
/***        Include files                                                 ***/
/****************************************************************************/

/****************************************************************************/
/***        Macro Definitions                                             ***/
/****************************************************************************/

/****************************************************************************/
/***        Type Definitions                                              ***/
/****************************************************************************/

/** Enumerated list of states for receive state machine */
typedef enum
{
    E_STATE_RX_WAIT_START,
    E_STATE_RX_WAIT_TYPEMSB,
    E_STATE_RX_WAIT_TYPELSB,
    E_STATE_RX_WAIT_LENMSB,
    E_STATE_RX_WAIT_LENLSB,
    E_STATE_RX_WAIT_CRC,
    E_STATE_RX_WAIT_DATA,
}teSL_RxState;

/****************************************************************************/
/***        Local Function Prototypes                                     ***/
/****************************************************************************/

/****************************************************************************
 *
 * NAME: u8SL_CalculateCRC
 *
 * DESCRIPTION:
 * Calculate CRC of packet
 *
 * PARAMETERS: Name                   RW  Usage
 *             u8Type                 R   Message type
 *             u16Length              R   Message length
 *             pu8Data                R   Message payload
 * RETURNS:
 * CRC of packet
 ****************************************************************************/
u8 u8SL_CalculateCRC(u16 u16Type, u16 u16Length, u8 *pu8Data)
{

    int n;
    u8 u8CRC;

    u8CRC  = (u16Type   >> 0) & 0xff;
    u8CRC ^= (u16Type   >> 8) & 0xff;
    u8CRC ^= (u16Length >> 0) & 0xff;
    u8CRC ^= (u16Length >> 8) & 0xff;

    for(n = 0; n < u16Length; n++)
    {
        u8CRC ^= pu8Data[n];
    }

    return(u8CRC);
}

u8 slTxBuffer[256];

u8 sl_usbTxMsg(u16 u16Type, u16 u16Length, u8 *pu8Data){
	if(!USBCDC_IsAvailable()){
		return ZBHCI_TX_BUSY;
	}
	u8 u8CRC;
	u8CRC = u8SL_CalculateCRC(u16Type, u16Length, pu8Data);
	slTxBuffer[0] = u16Type>>8;
	slTxBuffer[1] = u16Type;

	slTxBuffer[2] = u16Length>>8;
	slTxBuffer[3] = u16Length;

	slTxBuffer[4] = u8CRC;

	memcpy(slTxBuffer+5,pu8Data,u16Length);
	usbRwTx(slTxBuffer,u16Length+5);
}


void sl_txByte(bool bSpecialCharacter, u8 u8Data)
{
    if(!bSpecialCharacter && u8Data < 0x10)
    {
        /* Send escape character and escape byte */
        u8Data ^= 0x10;
        usbWriteByte(SL_ESC_CHAR);
    }
    usbWriteByte(u8Data);
}

u8 sl_txMsg(u16 u16Type, u16 u16Length, u8 *pu8Data)
{
	if(USBCDC_TxBusy()){
		return ZBHCI_TX_BUSY;
	}

	int n;
	u8 u8CRC;
	u8CRC = u8SL_CalculateCRC(u16Type, u16Length, pu8Data);
	/* Send start character */
	sl_txByte(TRUE, SL_START_CHAR);

	/* Send message type */
	sl_txByte(FALSE, (u16Type >> 8) & 0xff);
	sl_txByte(FALSE, (u16Type >> 0) & 0xff);

	/* Send message length */
	sl_txByte(FALSE, (u16Length >> 8) & 0xff);
	sl_txByte(FALSE, (u16Length >> 0) & 0xff);
	/* Send message checksum */
	sl_txByte(FALSE, u8CRC);
	/* Send message payload */
	for(n = 0; n < u16Length; n++)
	{
		sl_txByte(FALSE, pu8Data[n]);
	}
	/* Send end character */
	sl_txByte(TRUE, SL_END_CHAR);
	return ZBHCI_TX_SUCCESS;
}
/***********************************************************************************
 * @brief	Convert received message from control bridge software
 * @return	0~255 resolved byte length
 * 			0xf0000000
 */
u8 sl_convertRxMessage(u8 *buf,u8 len){
	u8 rPtr=0;
	u8 wPtr = 0;

	if(buf[0] == SL_START_CHAR){
		//A new packet
		rPtr++;
	}
	while((buf[rPtr] != SL_END_CHAR)&&(rPtr<len)){
		switch(buf[rPtr]){
			case SL_ESC_CHAR:
			{
				buf[wPtr++] = buf[++rPtr]^0x10;
			}
			break;
			default:{
				buf[wPtr++] = buf[rPtr];
			}
			break;
		}
		rPtr++;
	}
	return wPtr;
}
