
#ifndef ZBHCI_H
#define	ZBHCI_H

/** Macro to send a log message to the host machine
 *  First byte of the message is the level (0-7).
 *  Remainder of message is char buffer containing ascii message
 */

/****************************************************************************/
/***        Type Definitions                                              ***/
/****************************************************************************/
#define	USE_NXP_SFTWARE				0

/** Serial link message types */
typedef enum
{

    ZBHCI_MSG_STATUS                                            =   0x8000,
    ZBHCI_MSG_LOG                                               =   0x8001,
    ZBHCI_MSG_DATA_INDICATION                                   =   0x8002,//Report received data to HOST

    ZBHCI_MSG_NODE_CLUSTER_LIST                                 =   0x8003,
    ZBHCI_MSG_NODE_ATTRIBUTE_LIST                               =   0x8004,
    ZBHCI_MSG_NODE_COMMAND_ID_LIST                              =   0x8005,
    ZBHCI_MSG_NODE_NON_FACTORY_NEW_RESTART                      =   0x8006,
    ZBHCI_MSG_NODE_FACTORY_NEW_RESTART                          =   0x8007,
    ZBHCI_MSG_GET_VERSION                                       =   0x0010,
    ZBHCI_MSG_VERSION_LIST                                      =   0x8010,

	//Device management(self-control) CMDs
	ZBHCI_MSG_RESET                                             =   0x0011,//Required
	ZBHCI_MSG_ERASE_PERSISTENT_DATA                             =   0x0012,//Required
	ZBHCI_MSG_ZLL_FACTORY_NEW                                   =   0x0013,

	ZBHCI_MSG_PERMIT_JOIN_ST_GET                                =   0x0014,
	ZBHCI_MSG_PERMIT_JOIN_ST_GET_RESPONSE                       =   0x8014,

    ZBHCI_MSG_SET_EXT_PANID                                     =   0x0020,//Required
    ZBHCI_MSG_SET_CHANNELMASK                                   =   0x0021,//Required
    ZBHCI_MSG_SET_SECURITY                                      =   0x0022,//Required
    ZBHCI_MSG_SET_DEVICETYPE                                    =   0x0023,

    ZBHCI_MSG_START_NETWORK                                     =   0x0024,//Required
	ZBHCI_MSG_NETWORK_JOINED_FORMED                             =   0x8024,//Required

    ZBHCI_MSG_START_SCAN                                        =   0x0025,//Required
    ZBHCI_MSG_NETWORK_REMOVE_DEVICE                             =   0x0026,//Required
    ZBHCI_MSG_NETWORK_WHITELIST_ENABLE                          =   0x0027,

    ZBHCI_MSG_ADD_AUTHENTICATE_DEVICE                           =   0x0028,
	ZBHCI_MSG_AUTHENTICATE_DEVICE_RESPONSE                      =   0x8028,

    ZBHCI_MSG_OUTOFBAND_COMMISSIONING_DATA_REQ                  =   0x0029,
    ZBHCI_MSG_OUTOFBAND_COMMISSIONING_DATA_RSP                  =   0x8029,

    ZBHCI_MSG_UPDATE_AUTHENTICATE_DEVICE                        =   0x002A,

	//ZDO-APS Layer related functions
	ZBHCI_MSG_USER_DESC_SET                                     =   0x002B,
	ZBHCI_MSG_USER_DESC_NOTIFY                                  =   0x802B,
    ZBHCI_MSG_USER_DESC_REQ                                     =   0x002C,//Required
    ZBHCI_MSG_USER_DESC_RSP                                     =   0x802C,//Required
    ZBHCI_MSG_BIND                                              =   0x0030,//Required
    ZBHCI_MSG_BIND_RESPONSE                                     =   0x8030,//Required
    ZBHCI_MSG_UNBIND                                            =   0x0031,//Required
    ZBHCI_MSG_UNBIND_RESPONSE                                   =   0x8031,//Required
    ZBHCI_MSG_BIND_GROUP                                        =   0x0032,//Required
    ZBHCI_MSG_BIND_GROUP_RESPONSE                               =   0x8032,//Required
    ZBHCI_MSG_UNBIND_GROUP                                      =   0x0033,//Required
    ZBHCI_MSG_UNBIND_GROUP_RESPONSE                             =   0x8033,//Required
	ZBHCI_MSG_COMPLEX_DESCRIPTOR_REQUEST                        =   0x0034,
	ZBHCI_MSG_COMPLEX_DESCRIPTOR_RESPONSE                       =   0x8034,
    ZBHCI_MSG_NETWORK_ADDRESS_REQUEST                           =   0x0040,//Required
    ZBHCI_MSG_NETWORK_ADDRESS_RESPONSE                          =   0x8040,//Required
    ZBHCI_MSG_IEEE_ADDRESS_REQUEST                              =   0x0041,//Required
    ZBHCI_MSG_IEEE_ADDRESS_RESPONSE                             =   0x8041,//Required
    ZBHCI_MSG_NODE_DESCRIPTOR_REQUEST                           =   0x0042,//Required
    ZBHCI_MSG_NODE_DESCRIPTOR_RESPONSE                          =   0x8042,//Required
    ZBHCI_MSG_SIMPLE_DESCRIPTOR_REQUEST                         =   0x0043,//Required
    ZBHCI_MSG_SIMPLE_DESCRIPTOR_RESPONSE                        =   0x8043,//Required
    ZBHCI_MSG_POWER_DESCRIPTOR_REQUEST                          =   0x0044,//Required
    ZBHCI_MSG_POWER_DESCRIPTOR_RESPONSE                         =   0x8044,//Required
    ZBHCI_MSG_ACTIVE_ENDPOINT_REQUEST                           =   0x0045,//Required
    ZBHCI_MSG_ACTIVE_ENDPOINT_RESPONSE                          =   0x8045,//Required
    ZBHCI_MSG_MATCH_DESCRIPTOR_REQUEST                          =   0x0046,//Required
    ZBHCI_MSG_MATCH_DESCRIPTOR_RESPONSE                         =   0x8046,//Required
    ZBHCI_MSG_MANAGEMENT_LEAVE_REQUEST                          =   0x0047,//Required
    ZBHCI_MSG_MANAGEMENT_LEAVE_RESPONSE                         =   0x8047,//Required

    ZBHCI_MSG_LEAVE_INDICATION                                  =   0x8048,//Required
    ZBHCI_MSG_PERMIT_JOINING_REQUEST                            =   0x0049,//Required
    ZBHCI_MSG_PERMIT_JOINING_RESPONSE                           =   0x8049,//Required
    ZBHCI_MSG_MANAGEMENT_NETWORK_UPDATE_REQUEST                 =   0x004A,//Required
    ZBHCI_MSG_MANAGEMENT_NETWORK_UPDATE_RESPONSE                =   0x804A,//Required
    ZBHCI_MSG_SYSTEM_SERVER_DISCOVERY                           =   0x004B,//Required
    ZBHCI_MSG_SYSTEM_SERVER_DISCOVERY_RESPONSE                  =   0x804B,//Required
    ZBHCI_MSG_LEAVE_REQUEST                                     =   0x004C,//Required
    ZBHCI_MSG_DEVICE_ANNOUNCE                                   =   0x004D,//Required
    ZBHCI_MSG_MANAGEMENT_LQI_REQUEST                            =   0x004E,//Required
    ZBHCI_MSG_MANAGEMENT_LQI_RESPONSE                           =   0x804E,//Required
	ZBHCI_MSG_MANY_TO_ONE_ROUTE_REQUEST                         =   0x004F,


	//Cluster related CMDs
    /* Basic Cluster */
    ZBHCI_MSG_BASIC_RESET_TO_FACTORY_DEFAULTS                   =   0x0050,//Required
    ZBHCI_MSG_BASIC_RESET_TO_FACTORY_DEFAULTS_RESPONSE          =   0x8050,//Required

    /* Group Cluster */
    ZBHCI_MSG_ADD_GROUP                                         =   0x0060,//Required
    ZBHCI_MSG_ADD_GROUP_RESPONSE                                =   0x8060,//Required
    ZBHCI_MSG_VIEW_GROUP                                        =   0x0061,//Required
    ZBHCI_MSG_VIEW_GROUP_RESPONSE                               =   0x8061,//Required
    ZBHCI_MSG_GET_GROUP_MEMBERSHIP                              =   0x0062,//Required
    ZBHCI_MSG_GET_GROUP_MEMBERSHIP_RESPONSE                     =   0x8062,//Required
    ZBHCI_MSG_REMOVE_GROUP                                      =   0x0063,//Required
    ZBHCI_MSG_REMOVE_GROUP_RESPONSE                             =   0x8063,//Required
    ZBHCI_MSG_REMOVE_ALL_GROUPS                                 =   0x0064,//Required
    ZBHCI_MSG_ADD_GROUP_IF_IDENTIFY                             =   0x0065,//Required

    /* Identify Cluster */
    ZBHCI_MSG_IDENTIFY_SEND                                     =   0x0070,//Required
    ZBHCI_MSG_IDENTIFY_QUERY                                    =   0x0071,//Required
    ZBHCI_MSG_IDENTIFY_LOCAL_ACTIVE                             =   0x807a,//Required

    /* Level Cluster */
    ZBHCI_MSG_MOVE_TO_LEVEL                                     =   0x0080,//Required
    ZBHCI_MSG_MOVE_TO_LEVEL_ONOFF                               =   0x0081,//Required
    ZBHCI_MSG_MOVE_STEP                                         =   0x0082,//Required
    ZBHCI_MSG_MOVE_STOP_MOVE                                    =   0x0083,//Required
    ZBHCI_MSG_MOVE_STOP_ONOFF                                   =   0x0084,//Required

	/* On/Off Cluster */
	ZBHCI_MSG_ONOFF_NOEFFECTS                                   =   0x0092,//Required
	ZBHCI_MSG_ONOFF_TIMED                                       =   0x0093,//Required
	ZBHCI_MSG_ONOFF_EFFECTS                                     =   0x0094,//Required
	ZBHCI_MSG_ONOFF_UPDATE                                      =   0x8095,//Required

    /* Scenes Cluster */
    ZBHCI_MSG_VIEW_SCENE                                        =   0x00A0,//Required
    ZBHCI_MSG_VIEW_SCENE_RESPONSE                               =   0x80A0,//Required
    ZBHCI_MSG_ADD_SCENE                                         =   0x00A1,//Required
    ZBHCI_MSG_ADD_SCENE_RESPONSE                                =   0x80A1,//Required
    ZBHCI_MSG_REMOVE_SCENE                                      =   0x00A2,//Required
    ZBHCI_MSG_REMOVE_SCENE_RESPONSE                             =   0x80A2,//Required
    ZBHCI_MSG_REMOVE_ALL_SCENES                                 =   0x00A3,//Required
    ZBHCI_MSG_REMOVE_ALL_SCENES_RESPONSE                        =   0x80A3,//Required
    ZBHCI_MSG_STORE_SCENE                                       =   0x00A4,//Required
    ZBHCI_MSG_STORE_SCENE_RESPONSE                              =   0x80A4,//Required
    ZBHCI_MSG_RECALL_SCENE                                      =   0x00A5,//Required
    ZBHCI_MSG_SCENE_MEMBERSHIP_REQUEST                          =   0x00A6,//Required
    ZBHCI_MSG_SCENE_MEMBERSHIP_RESPONSE                         =   0x80A6,//Required

	 /* Scenes Cluster */
	ZBHCI_MSG_ADD_ENHANCED_SCENE                                =   0x00A7,
	ZBHCI_MSG_VIEW_ENHANCED_SCENE                               =   0x00A8,
	ZBHCI_MSG_COPY_SCENE                                        =   0x00A9,

    /* Colour Cluster */
    ZBHCI_MSG_MOVE_TO_HUE                                       =   0x00B0,
    ZBHCI_MSG_MOVE_HUE                                          =   0x00B1,
    ZBHCI_MSG_STEP_HUE                                          =   0x00B2,
    ZBHCI_MSG_MOVE_TO_SATURATION                                =   0x00B3,
    ZBHCI_MSG_MOVE_SATURATION                                   =   0x00B4,
    ZBHCI_MSG_STEP_SATURATION                                   =   0x00B5,
    ZBHCI_MSG_MOVE_TO_HUE_SATURATION                            =   0x00B6,
    ZBHCI_MSG_MOVE_TO_COLOUR                                    =   0x00B7,
    ZBHCI_MSG_MOVE_COLOUR                                       =   0x00B8,
    ZBHCI_MSG_STEP_COLOUR                                       =   0x00B9,
	ZBHCI_MSG_ENHANCED_MOVE_TO_HUE                              =   0x00BA,
	ZBHCI_MSG_ENHANCED_MOVE_HUE                                 =   0x00BB,
	ZBHCI_MSG_ENHANCED_STEP_HUE                                 =   0x00BC,
	ZBHCI_MSG_ENHANCED_MOVE_TO_HUE_SATURATION                   =   0x00BD,
	ZBHCI_MSG_COLOUR_LOOP_SET                                   =   0x00BE,
	ZBHCI_MSG_STOP_MOVE_STEP                                    =   0x00BF,
	ZBHCI_MSG_MOVE_TO_COLOUR_TEMPERATURE                        =   0x00C0,
	ZBHCI_MSG_MOVE_COLOUR_TEMPERATURE                           =   0x00C1,
	ZBHCI_MSG_STEP_COLOUR_TEMPERATURE                           =   0x00C2,

    /* ZLL Commands */
    /* Touchlink */
    ZBHCI_MSG_INITIATE_TOUCHLINK                                =   0x00D0,//Required
    ZBHCI_MSG_TOUCHLINK_STATUS                                  =   0x00D1,//Required
    ZBHCI_MSG_TOUCHLINK_FACTORY_RESET                           =   0x00D2,//Required
    /* Identify Cluster */
    ZBHCI_MSG_IDENTIFY_TRIGGER_EFFECT                           =   0x00E0,//Required

    /* Door Lock Cluster */
    ZBHCI_MSG_LOCK_UNLOCK_DOOR                                  =   0x00F0,

    /* ZHA Commands */
    ZBHCI_MSG_READ_ATTRIBUTE_REQUEST                             =  0x0100,
    ZBHCI_MSG_READ_ATTRIBUTE_RESPONSE                            =  0x8100,
    ZBHCI_MSG_DEFAULT_RESPONSE                                   =  0x8101,
    ZBHCI_MSG_REPORT_IND_ATTR_RESPONSE                           =  0x8102,
    ZBHCI_MSG_WRITE_ATTRIBUTE_REQUEST                            =  0x0110,
    ZBHCI_MSG_WRITE_ATTRIBUTE_RESPONSE                           =  0x8110,
    ZBHCI_MSG_CONFIG_REPORTING_REQUEST                           =  0x0120,
    ZBHCI_MSG_CONFIG_REPORTING_RESPONSE                          =  0x8120,
    ZBHCI_MSG_REPORT_ATTRIBUTES                                  =  0x8121,
    ZBHCI_MSG_READ_REPORT_CONFIG_REQUEST                         =  0x0122,
    ZBHCI_MSG_READ_REPORT_CONFIG_RESPONSE                        =  0x8122,
    ZBHCI_MSG_ATTRIBUTE_DISCOVERY_REQUEST                        =  0x0140,
    ZBHCI_MSG_ATTRIBUTE_DISCOVERY_RESPONSE                       =  0x8140,
    ZBHCI_MSG_ATTRIBUTE_EXT_DISCOVERY_REQUEST                    =  0x0141,
    ZBHCI_MSG_ATTRIBUTE_EXT_DISCOVERY_RESPONSE                   =  0x8141,
    ZBHCI_MSG_COMMAND_RECEIVED_DISCOVERY_REQUEST                 =  0x0150,
    ZBHCI_MSG_COMMAND_RECEIVED_DISCOVERY_INDIVIDUAL_RESPONSE     =  0x8150,
    ZBHCI_MSG_COMMAND_RECEIVED_DISCOVERY_RESPONSE                =  0x8151,
    ZBHCI_MSG_COMMAND_GENERATED_DISCOVERY_REQUEST                =  0x0160,
    ZBHCI_MSG_COMMAND_GENERATED_DISCOVERY_INDIVIDUAL_RESPONSE    =  0x8160,
    ZBHCI_MSG_COMMAND_GENERATED_DISCOVERY_RESPONSE               =  0x8161,

    ZBHCI_MSG_SAVE_PDM_RECORD                                    =  0x0200,
    ZBHCI_MSG_SAVE_PDM_RECORD_RESPONSE                           =  0x8200,
    ZBHCI_MSG_LOAD_PDM_RECORD_REQUEST                            =  0x0201,
    ZBHCI_MSG_LOAD_PDM_RECORD_RESPONSE                           =  0x8201,
    ZBHCI_MSG_DELETE_PDM_RECORD                                  =  0x0202,

    ZBHCI_MSG_PDM_HOST_AVAILABLE                                 =  0x0300,
    ZBHCI_MSG_ASC_LOG_MSG                                        =  0x0301,
    ZBHCI_MSG_ASC_LOG_MSG_RESPONSE                               =  0x8301,
    ZBHCI_MSG_PDM_HOST_AVAILABLE_RESPONSE                        =  0x8300,


    /* IAS Cluster */
    ZBHCI_MSG_SEND_IAS_ZONE_ENROLL_RSP                           =  0x0400,//Required
    ZBHCI_MSG_IAS_ZONE_STATUS_CHANGE_NOTIFY                      =  0x8401,//Required

    /* OTA Cluster */
    ZBHCI_MSG_LOAD_NEW_IMAGE                                     =  0x0500,//Required
    ZBHCI_MSG_BLOCK_REQUEST                                      =  0x8501,//Required
    ZBHCI_MSG_BLOCK_SEND                                         =  0x0502,//Required
    ZBHCI_MSG_UPGRADE_END_REQUEST                                =  0x8503,//Required
    ZBHCI_MSG_UPGRADE_END_RESPONSE                               =  0x0504,//Required
    ZBHCI_MSG_IMAGE_NOTIFY                                       =  0x0505,//Required
    ZBHCI_MSG_SEND_WAIT_FOR_DATA_PARAMS                          =  0x0506,//Required
    ZBHCI_MSG_SEND_RAW_APS_DATA_PACKET                          =   0x0530,//Required

    ZBHCI_MSG_NWK_RECOVERY_EXTRACT_REQ                           =  0x0600,
    ZBHCI_MSG_NWK_RECOVERY_EXTRACT_RSP                           =  0x8600,
    ZBHCI_MSG_NWK_RECOVERY_RESTORE_REQ                           =  0x0601,
    ZBHCI_MSG_NWK_RECOVERY_RESTORE_RSP                           =  0x8601,

    ZBHCI_MSG_ROUTE_DISCOVERY_CONFIRM                            =  0x8701,
    ZBHCI_MSG_APS_DATA_CONFIRM_FAILED                            =  0x8702,

	ZBHCI_MSG_AHI_DIO_SET_DIRECTION								= 0x0801,
	ZBHCI_MSG_AHI_DIO_SET_OUTPUT								= 0x0802,
	ZBHCI_MSG_AHI_DIO_READ_INPUT								= 0x0803,
	ZBHCI_MSG_AHI_DIO_READ_INPUT_RSP							= 0x8803,
	ZBHCI_MSG_AHI_SET_TX_POWER									= 0x0806,
} teSL_MsgType;
typedef enum
{
	ZBHCI_MSG_AHI_START									= 0x0800,
	ZBHCI_MSG_AHI_END									= 0x0A00,

}teSL_MsgTypeRange;

/** Status message */
typedef struct
{
    enum
    {
        ZBHCI_MSG_STATUS_SUCCESS,
        ZBHCI_MSG_STATUS_INCORRECT_PARAMETERS,
        ZBHCI_MSG_STATUS_UNHANDLED_COMMAND,
        ZBHCI_MSG_STATUS_BUSY,
        ZBHCI_MSG_STATUS_STACK_ALREADY_STARTED,
    }  eStatus;
    u8 u8SeqNum;
    char                acMessage[];            /**< Optional message */
}  tsSL_Msg_Status;


typedef struct{
	u8	msgType16H;
	u8	msgType16L;

	u8	msgLen16H;
	u8	msgLen16L;

	u8	checkSum;
	u8	pData[1];
}zbhci_msg_t;


/** Structure containing a log message for passing to the host via the serial link */
typedef struct
{
    enum
    {
        ZBHCI_LOG_EMERG,
        ZBHCI_LOG_ALERT,
        ZBHCI_LOG_CRIT,
        ZBHCI_LOG_ERR,
        ZBHCI_LOG_WARNING,
        ZBHCI_LOG_NOTICE,
        ZBHCI_LOG_INFO,
        ZBHCI_LOG_DEBUG,
    }eLevel;
    u8 au8Message[256];
} tsSL_Msg_Log;


//define the spp rx cb function
typedef enum{
	ZBHCI_TX_SUCCESS,
	ZBHCI_TX_BUFFERFULL,
	ZBHCI_TX_BUSY,
	ZBHCI_TX_FAILED
}zbhciTx_e;

#define ZB_LEBESWAP(ptr,len)								\
	int	cl = len>>1;									\
	for(int i=0; i<cl;i++){						\
		unsigned char temp = ptr[len - i - 1];				\
		ptr[len - i - 1] = ptr[i];							\
		ptr[i] = temp;										\
	}														\


#define ZB_IEEE_ADDR_REVERT(tar,addr)						\
	for(int i=0; i<EXT_ADDR_LEN;i++){						\
		(tar)[i]=(addr)[EXT_ADDR_LEN - i - 1];					\
	}														\

#define			ZB_LEBESWAPU16(u16Value)						(u16Value = (u16Value>>8)|(u16Value<<8))

typedef struct{
	u8			st;
	u8			shortAddrH;
	u8			shortAddrL;
	addrExt_t	extAddr;
	u8			channel;
}hci_nwkStartCnfMsg_t;

typedef struct{
	u8			shortAddrH;
	u8			shortAddrL;
	addrExt_t	extAddr;
	u8			mc;
}hci_devAnncMsg_t;

#define		MAX_MATCHRSP_LEN		5
typedef struct{
	u8	seq;
	u8	st;
	u8	shortAddrH;
	u8	shortAddrL;
	u8	matchLen;
	u8	matchRes[MAX_MATCHRSP_LEN];

}hci_matchRsp_t;

typedef struct{
	u8			shortAddrH;
	u8			shortAddrL;
	addrExt_t	extAddr;
	u8			mc;
}hci_leaveIndMsg_t;


typedef struct{
	u8		sqn;
	u8		st;
	u8		nwkAddrH;
	u8		nwkAddrL;

	u8		manuCodeH;
	u8		manuCodeL;
	u8		maxRxSizeH;
	u8		maxRxSizeL;

	u8		maxTxSizeH;
	u8		maxTxSizeL;
	u8		servMaskH;
	u8		servMaskL;

	u8		descCap;
	u8		macCap;
	u8		maxBuffSize;
	u8		bfH;

	u8		bfL;
}hci_nodeDescRspMsg_t;

#define			MAX_REQ_CLST_NUM			8
typedef struct{
	u8		sqn;
	u8		st;
	u8		nwkAddrH;
	u8		nwkAddrL;

	u8		msgLen;
	u8		ep;
	u8		profileIdH;
	u8		profileIdL;

	u8		deviceIdH;
	u8		deviceIdL;
	u8		appVer;

	u8		inputClstNum;
	u8		payload[MAX_REQ_CLST_NUM*4 + 1];
}hci_simpleDescRspMsg_t;

typedef enum{
	ZBHCI_ADDRMODE_BOUND,
	ZBHCI_ADDRMODE_GROUP,
	ZBHCI_ADDRMODE_SHORT,
	ZBHCI_ADDRMODE_IEEE=0x03,
	ZBHCI_ADDRMODE_BRC,
	ZBHCI_ADDRMODE_NOTX = 0x05,
	ZBHCI_ADDRMODE_BOUNDNOACK = 0x06,
	ZBHCI_ADDRMODE_SHORTNOACK,
	ZBHCI_ADDRMODE_IEEENOACK
}zbhciTxMode_e;
typedef void (*zbhciRxCbFun)(u8 *buf, u8 len);
typedef void (*zbhciTxDoneCbFun)(u8 *buf);
#endif
