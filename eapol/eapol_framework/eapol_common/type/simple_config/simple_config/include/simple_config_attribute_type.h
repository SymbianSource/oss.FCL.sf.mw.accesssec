/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

#if !defined(_SIMPLE_CONFIG_ATTRIBUTE_TYPE_H_)
#define _SIMPLE_CONFIG_ATTRIBUTE_TYPE_H_

/** @file */

//----------------------------------------------------------------------------

/**
 * This is enumeration of Simple Config Type-Length-Value (TLV) types.
 */
enum simple_config_Attribute_Type_e
{
	simple_config_Attribute_Type_None = 0x0000, ///< This is initialization value.

	simple_config_Attribute_Type_AP_Channel = 0x1001,
	simple_config_Attribute_Type_First_Correct_Value = simple_config_Attribute_Type_AP_Channel,

	simple_config_Attribute_Type_Association_State = 0x1002,
	simple_config_Attribute_Type_Authentication_Type = 0x1003,
	simple_config_Attribute_Type_Authentication_Type_Flags = 0x1004,
	simple_config_Attribute_Type_Authenticator = 0x1005,
	simple_config_Attribute_Type_Config_Methods = 0x1008,
	simple_config_Attribute_Type_Configuration_Error = 0x1009,
	simple_config_Attribute_Type_Confirmation_URL4 = 0x100A,
	simple_config_Attribute_Type_Confirmation_URL6 = 0x100B,
	simple_config_Attribute_Type_Connection_Type = 0X100C,
	simple_config_Attribute_Type_Connection_Type_Flags = 0X100D,
	simple_config_Attribute_Type_Credential = 0X100E,
	simple_config_Attribute_Type_Device_Name = 0x1011,
	simple_config_Attribute_Type_Device_Password_ID = 0x1012,
	simple_config_Attribute_Type_E_Hash1 = 0x1014,
	simple_config_Attribute_Type_E_Hash2 = 0x1015,
	simple_config_Attribute_Type_E_SNonce1 = 0x1016,
	simple_config_Attribute_Type_E_SNonce2 = 0x1017,
	simple_config_Attribute_Type_Encrypted_Settings = 0x1018,
	simple_config_Attribute_Type_Encryption_Type = 0X100F,
	simple_config_Attribute_Type_Encryption_Type_Flags = 0x1010,
	simple_config_Attribute_Type_Enrollee_Nonce = 0x101A,
	simple_config_Attribute_Type_Feature_ID = 0x101B,
	simple_config_Attribute_Type_Identity = 0X101C,
	simple_config_Attribute_Type_Identity_Proof = 0X101D,
	simple_config_Attribute_Type_Key_Wrap_Authenticator = 0x101E,
	simple_config_Attribute_Type_Key_Identifier = 0X101F,
	simple_config_Attribute_Type_MAC_Address = 0x1020,
	simple_config_Attribute_Type_Manufacturer = 0x1021,
	simple_config_Attribute_Type_Message_Type = 0x1022,
	simple_config_Attribute_Type_Model_Name = 0x1023,
	simple_config_Attribute_Type_Model_Number = 0x1024,
	simple_config_Attribute_Type_Network_Index = 0x1026,
	simple_config_Attribute_Type_Network_Key = 0x1027,
	simple_config_Attribute_Type_Network_Key_Index = 0x1028,
	simple_config_Attribute_Type_New_Device_Name = 0x1029,
	simple_config_Attribute_Type_New_Password = 0x102A,
	simple_config_Attribute_Type_OOB_Device_Password = 0X102C,
	simple_config_Attribute_Type_OS_Version = 0X102D,
	simple_config_Attribute_Type_Power_Level = 0X102F,
	simple_config_Attribute_Type_PSK_Current = 0x1030,
	simple_config_Attribute_Type_PSK_Max = 0x1031,
	simple_config_Attribute_Type_Public_Key = 0x1032,
	simple_config_Attribute_Type_Radio_Enabled = 0x1033,
	simple_config_Attribute_Type_Reboot = 0x1034,
	simple_config_Attribute_Type_Registrar_Current = 0x1035,
	simple_config_Attribute_Type_Registrar_Established = 0x1036,
	simple_config_Attribute_Type_Registrar_List = 0x1037,
	simple_config_Attribute_Type_Registrar_Max = 0x1038,
	simple_config_Attribute_Type_Registrar_Nonce = 0x1039,
	simple_config_Attribute_Type_Request_Type = 0x103A,
	simple_config_Attribute_Type_Response_Type = 0x103B,
	simple_config_Attribute_Type_RF_Band = 0X103C,
	simple_config_Attribute_Type_R_Hash1 = 0X103D,
	simple_config_Attribute_Type_R_Hash2 = 0X103E,
	simple_config_Attribute_Type_R_SNonce1 = 0X103F,
	simple_config_Attribute_Type_R_SNonce2 = 0x1040,
	simple_config_Attribute_Type_Selected_Registrar = 0x1041,
	simple_config_Attribute_Type_Serial_Number = 0x1042,
	simple_config_Attribute_Type_Simple_Config_State = 0x1044,
	simple_config_Attribute_Type_SSID = 0x1045,
	simple_config_Attribute_Type_Total_Networks = 0x1046,
	simple_config_Attribute_Type_UUID_E = 0x1047,
	simple_config_Attribute_Type_UUID_R = 0x1048,
	simple_config_Attribute_Type_Vendor_Extension = 0x1049,
	simple_config_Attribute_Type_Version = 0x104A,
	simple_config_Attribute_Type_X_509_Certificate_Request = 0x104B,
	simple_config_Attribute_Type_X_509_Certificate = 0x104C,
	simple_config_Attribute_Type_EAP_Identity = 0x104D,
	simple_config_Attribute_Type_Message_Counter = 0x104E,
	simple_config_Attribute_Type_Public_Key_Hash = 0x104F,
	simple_config_Attribute_Type_Rekey_Key = 0x1050,
	simple_config_Attribute_Type_Key_Lifetime = 0x1051,
	simple_config_Attribute_Type_Permitted_Config_Methods = 0x1052,
	simple_config_Attribute_Type_Selected_Registrar_Config_Methods = 0x1053,
	simple_config_Attribute_Type_Primary_Device_Type = 0x1054,
	simple_config_Attribute_Type_Secondary_Device_Type_List = 0x1055,
	simple_config_Attribute_Type_Portable_Device = 0x1056,
	simple_config_Attribute_Type_AP_Setup_Locked = 0x1057,
	simple_config_Attribute_Type_Application_List = 0x1058,
	simple_config_Attribute_Type_EAP_Type = 0x1059,
	simple_config_Attribute_Type_Initialization_Vector = 0x1060,
	simple_config_Attribute_Type_Key_Provided_Automatically = 0x1061,
	simple_config_Attribute_Type_802_1X_Enabled = 0x1062,
	simple_config_Attribute_Type_Last_Correct_Value = simple_config_Attribute_Type_802_1X_Enabled,
};


//----------------------------------------------------------------------------

#endif //#if !defined(_SIMPLE_CONFIG_ATTRIBUTE_TYPE_H_)

// End.
