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
* Description:  This file defines the constants and types of the protected setup protocol.
*
*/

/*
* %version: 26 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 600 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "simple_config_types.h"


/** @file simple_config_types.cpp 
 */

//--------------------------------------------------

EAP_FUNC_EXPORT network_key_and_index_c::~network_key_and_index_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT network_key_and_index_c::network_key_and_index_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_network_key_index(0ul)
	, m_network_key(tools)
	, m_is_valid(false)
{
	if (m_network_key.get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u8_t network_key_and_index_c::get_network_key_index() const
{
	return m_network_key_index;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void network_key_and_index_c::set_network_key_index(u8_t index)
{
	m_network_key_index = index;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_variable_data_c * network_key_and_index_c::get_network_key()
{
	return &m_network_key;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_variable_data_c * network_key_and_index_c::get_network_key_const() const
{
	return &m_network_key;
}

//--------------------------------------------------

EAP_FUNC_EXPORT network_key_and_index_c * network_key_and_index_c::copy()
{
	network_key_and_index_c * const copy_object = new network_key_and_index_c(m_am_tools);
	if (copy_object == 0
		|| copy_object->get_is_valid() == false)
	{
		delete copy_object;
		return 0;
	}

	copy_object->set_network_key_index(get_network_key_index());

	eap_status_e status = copy_object->get_network_key()->set_copy_of_buffer(get_network_key());
	if (status != eap_status_ok)
	{
		delete copy_object;
		return 0;
	}

	return copy_object;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool network_key_and_index_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool network_key_and_index_c::get_is_valid_data()
{
	return get_is_valid() && get_network_key()->get_is_valid_data();
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT eap_simple_config_trace_string_c::~eap_simple_config_trace_string_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_simple_config_trace_string_c::eap_simple_config_trace_string_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_simple_config_trace_string_c::get_state_string(const simple_config_state_e state) const
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, simple_config_state_none)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_simple_config_start)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M1)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M2)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M3)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M4)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M5)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M6)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M7)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_M8)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_WSC_ACK)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_WSC_NACK)
	else EAP_IF_RETURN_STRING(state, simple_config_state_wait_WSC_DONE)
	else EAP_IF_RETURN_STRING(state, simple_config_state_pending_simple_config_messages_processed)
	else EAP_IF_RETURN_STRING(state, simple_config_state_simple_config_success)
	else EAP_IF_RETURN_STRING(state, simple_config_state_failure)
	else
#else
EAP_UNREFERENCED_PARAMETER(state);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown SIMPLE_CONFIG-state");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_simple_config_trace_string_c::get_message_type_string(const simple_config_Message_Type_e type) const
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, simple_config_Message_Type_None)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_Beacon)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_Probe_Request)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_Probe_Response)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M1)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M2)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M2D)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M3)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M4)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M5)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M6)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M7)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_M8)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_WSC_ACK)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_WSC_NACK)
	else EAP_IF_RETURN_STRING(type, simple_config_Message_Type_WSC_DONE)
	else
#else
	EAP_UNREFERENCED_PARAMETER(type);			
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown SIMPLE_CONFIG-message");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_simple_config_trace_string_c::get_attribute_type_string(const simple_config_Attribute_Type_e type) const
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_None)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_AP_Channel)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Association_State)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Authentication_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Authentication_Type_Flags)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Authenticator)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Config_Methods)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Configuration_Error)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Confirmation_URL4)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Confirmation_URL6)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Connection_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Connection_Type_Flags)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Credential)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Device_Name)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Device_Password_ID)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_E_Hash1)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_E_Hash2)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_E_SNonce1)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_E_SNonce2)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Encrypted_Settings)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Encryption_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Encryption_Type_Flags)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Enrollee_Nonce)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Feature_ID)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Identity)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Identity_Proof)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Key_Wrap_Authenticator)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Key_Identifier)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_MAC_Address)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Manufacturer)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Message_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Model_Name)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Model_Number)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Network_Index)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Network_Key)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Network_Key_Index)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_New_Device_Name)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_New_Password)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_OOB_Device_Password)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_OS_Version)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Power_Level)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_PSK_Current)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_PSK_Max)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Public_Key)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Radio_Enabled)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Reboot)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Registrar_Current)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Registrar_Established)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Registrar_List)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Registrar_Max)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Registrar_Nonce)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Request_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Response_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_RF_Band)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_R_Hash1)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_R_Hash2)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_R_SNonce1)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_R_SNonce2)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Selected_Registrar)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Serial_Number)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Simple_Config_State)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_SSID)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Total_Networks)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_UUID_E)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_UUID_R)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Vendor_Extension)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Version)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_X_509_Certificate_Request)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_X_509_Certificate)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_EAP_Identity)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Message_Counter)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Public_Key_Hash)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Rekey_Key)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Key_Lifetime)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Permitted_Config_Methods)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Selected_Registrar_Config_Methods)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Primary_Device_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Secondary_Device_Type_List)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Portable_Device)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_AP_Setup_Locked)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Application_List)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_EAP_Type)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Initialization_Vector)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_Key_Provided_Automatically)
	else EAP_IF_RETURN_STRING(type, simple_config_Attribute_Type_802_1X_Enabled)
	else
#else
	EAP_UNREFERENCED_PARAMETER(type);
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		return EAPL("Unknown Attribute Type");
	}
}

//--------------------------------------------------

// End.
