

#if SECURITY_ENABLE
#define		SECURITY_MODE_STANDARD 			1
#define		SECURITY_MODE_HIGH				(!SECURITY_MODE_STANDARD)
#define		SS_UPDATE_FRAMECOUNT_THRES		1024
#endif
typedef enum{
	SS_KEYREQ_TYPE_APPLK = 0x02,
	SS_KEYREQ_TYPE_TCLK = 0x04
}ss_keyReqType_e;

enum
{
  SS_SECUR_NO_ENCR,
  SS_SECUR_NWK_ENCR,
  SS_SECUR_APS_ENCR,
  SS_SECUR_MAC_ENCR
};
/**
   Key id - see 4.5.1.1.2
 */
enum{
  SS_SECUR_DATA_KEY,
  SS_SECUR_NWK_KEY,
  SS_SECUR_KEY_TRANSPORT_KEY,
  SS_SECUR_KEY_LOAD_KEY
};

//Key types
typedef enum{
	SS_TC_MASTER_KEY,//removed from zb 3.0
	SS_STANDARD_NETWORK_KEY = 0x01,
	SS_APP_MASTER_KEY,//removed from zb 3.0
	SS_APP_LINK_KEY = 0x03,
	SS_TC_LINK_KEY = 0x04,
	SS_HIGH_SECUR_NETWORK_KEY,//removed from zb 3.0
} ss_seKeyType_e;

typedef enum{
	SS_UNIQUE_LINK_KEY = 0x00,
	SS_GLOBAL_LINK_KEY = 0x01
}ss_linkKeytype_e;

typedef enum{
	SS_SEMODE_CENTRALIZED,
	SS_SEMODE_DISTRIBUTED
}ss_securityMode_e;

typedef enum{
	SS_PROVISIONAL_KEY,
	SS_UNVERIFIED_KEY,
	SS_VERIFIED_KEY
}ss_keyAttributes_e;


typedef struct
{
  u8		key[CCM_KEY_SIZE];
  u8		keySeqNum;
  u8		keyType;
}ss_material_set_t;

typedef enum{
	SS_PRECONFIGURED_NOKEY,
	SS_PRECONFIGURED_GLOBALLINKKEY,
	SS_PRECONFIGURED_UNIQUELLINKKEY,
	SS_PRECONFIGURED_NWKKEY
}ss_preconfiguredKey_e;


typedef struct{

	//This value set to TRUE will only allow devices know to TC join or rejoin
	bool	useWhiteList;
	// 0 ~ not support; 1 ~ support but not require; 2 ~ require the use of install code by JD, the useWhiteList would set to TRUE
	//interface need to be supported to input install code to TC
	u8		allowInstallCode;
	//Indicates whether or not devices are required to attempt to update their TCLK after joining. In centralized security network,
	//this value must be set to TRUE, the joining device must attempt TCLK update after joining the network.
	bool	updateTCLKrequired;
#ifdef ZB_COORDINATOR_ROLE
	//This values indicates whether or not TC allow new device join to the network, set to false in centralized security NWK will
	//reject any join request
	bool	allowJoins;
	//If TC allows rejoin using well known or default keys, a setting of FALSE means rejoins are only allowed with TCLK where the
	//KeyAttributes of the apsDeviceKeyPairSet entry indicates VERIFIED_KEY. This value set to FALSE in centralized security NWK.
	bool	allowRejoins;
	//0 ~ never; 1 ~ any device may request; 2 ~ only devices in the apsDeviceKeyPaireSet.
	//Set to 0 in network with higher level protocols for establishing link keys. Set to 1/2 in centralized security networks
	u8		allowTCLKrequest;

	u8		allowAppLKrequest;
#endif

}ss_tcPolicy_t;



typedef enum{
	KEYTYPE_PRO_MASK = BIT(0),
	KEYTYPE_UNVERIFY_MASK = BIT(1),
	KEYTYPE_VERIFIED_MASK = BIT(2)
}nvKeytpeMask_e;

typedef enum{
	SS_DEVKEYPAIR_SYNID_KEYATTR,
	SS_DEVKEYPAIR_SYNID_INCOMMINGFRAMECNT,
	SS_DEVKEYPAIR_SYNID_ALL
}ss_devKeyPairSyn_id;
#define		SS_DEVKEYPAIRNV_SPACE			32
#define		SS_DEVKEYPAIRMAXNUM_PERPAGE		128
typedef struct{
	u8					itemAvailable;
	addrExt_t			device_address;
	u8					linkKey[CCM_KEY_SIZE];		/* The actual value of the link key. */
	ss_keyAttributes_e 	keyAttr;
}ss_devPairNV_t;

#define		NV_ITEM_COPYLEN		25
typedef struct{
	addrExt_t			device_address;

	u8					linkKey[CCM_KEY_SIZE];		/* The actual value of the link key. */

	ss_keyAttributes_e 	keyAttr;
	ss_linkKeytype_e 	apsLinkKeyType;
	u8					used;
	u8					rsv;//used as mapping index to stack item

	u32					outgoingFrameCounter;
	u32					incomingFrmaeCounter;
}ss_dev_pair_set_t;

typedef struct{
	u32					nvAddr;
	u32					incomingFrmaeCounter;
}ss_devPairStack_t;

typedef struct{
	u32						outgoingFrameCounter;

	u32						prevOutgoingFrameCounter;
#ifdef ZB_COORDINATOR_ROLE
	ss_devPairStack_t		ssDeviceKeyPairSet[SECUR_N_DEVICE_PAIRSET];
	ss_dev_pair_set_t		ssDevKeyPairTem;//36
	u8						keyPairSetUsed;
#else
	ss_dev_pair_set_t		ssDeviceKeyPairSet[SECUR_N_DEVICE_PAIRSET];
#endif
	ss_material_set_t		nwkSecurMaterialSet[SECUR_N_SECUR_MATERIAL];
	addrExt_t				trust_center_address;
	u8						securityLevel:4;
	u8						secureAllFrames:1;
	u8						activeSecureMaterialIndex:2;
	u8						reserved:1;
	u8						activeKeySeqNum;
	ss_preconfiguredKey_e	preConfiguredKeyType;//pre-configured type, should be set during init state which used for ZDO auth
	ss_tcPolicy_t			tcPolicy;
}ss_info_base_t;


typedef struct{
	/*The extended 64-bit address of the device
	that is the parent of the child device that is
	requested to be removed, or the router
	device that is requested to be removed.*/
	addrExt_t			parentAddr;
	/*The extended 64-bit address of the target
	device that is requested to be removed. If a
	router device is requested to be removed,
	then the ParentAddress shall be the same
	as the TargetAddress.*/
	addrExt_t			targetExtAddr;
}ss_apsDevRemoveReq_t;

typedef struct{
	/*The extended 64-bit address of the child
	device that is requested to be removed*/
	addrExt_t			childExtAddr;
	/*The extended 64-bit address of the device
	 requesting that a child device be removed.*/
	addrExt_t			tcAddr;
}ss_apsDevRemoveInd_t;


bool ss_keyPreconfigured(void );
bool ss_linkKeyPreconfigured(void );
bool ss_masterKeyPreconfigured(void );
void ss_zdoNwkKeyConfigure(u8 *key, u8 i,u8 keyType);
u8 ss_apsAuxHdrfill(void *p, bool nwkKey/*, u8 cmdId*/);
u8 ss_apsDecryptFrame(void *p);
u8 ss_apsSecureFrame(void *p, u8 apsHdrAuxLen,u8 apsHdrLen, addrExt_t extAddr);
u8 ss_apsDeviceRemoveReq(ss_apsDevRemoveReq_t *p);

void zdo_ssInfoUpdate(void);
u8 zdo_ssInfoInit(void);
void zdo_ssInfoSaveToFlash();

/********************************************************************************************************
 * @brief	External used function for security service initialization
 *
 * @param	*nwkKey: parameter only used for TC, configured network key to be used in NWK layer security,
 * 						if NULL should use the default key
 * 			*linkKey: configured link key used during transport key procedure
 * 			keyType:	link key type used, global or private
 * 			enSecurity:	enable or disable security used
 * 			seMode: centralized mode or distributed mode
 * @return none
 */
void ss_securityModeInit(u8 *nwkKey, u8 *linkKey, ss_linkKeytype_e type, bool enSecurity, ss_securityMode_e seMode);

extern	ss_info_base_t ss_ib;
