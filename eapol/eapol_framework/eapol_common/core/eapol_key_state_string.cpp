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
* %version: 12 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 719 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eapol_key_state_string.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_key_state_string_c::~eapol_key_state_string_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eapol_key_state_string_c::eapol_key_state_string_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eapol_key_state_string_c::get_eapol_key_state_string(
	const eapol_key_state_e state)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(state, eapol_key_state_none)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_preauthenticated)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_eap_authentication_running)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_start)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_1)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_2)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_3)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_4_way_handshake_message_4)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_4_way_handshake_running)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_4_way_handshake_failed)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_4_way_handshake_successfull)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_group_key_handshake_message_1)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_group_key_handshake_message_2)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_group_key_handshake_failed)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_group_key_handshake_successfull)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wait_rc4_key_message)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_802_11i_authentication_terminated_unsuccessfull)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_802_11i_authentication_finished_successfull)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_reassociation_failed)
#if defined(EAP_USE_WPXM)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wpxm_reassociation_finished_successfull)
#endif //#if defined(EAP_USE_WPXM)
#if defined(USE_WAPI_CORE)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wapi_authentication_terminated_unsuccessfull)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wapi_authentication_finished_successfull)
	else EAP_IF_RETURN_STRING(state, eapol_key_state_wapi_authentication_running)
#endif //#if defined(USE_WAPI_CORE)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(state);

		return EAPL("Unknown EAPOL-Key Handshake state");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eapol_key_state_string_c::get_eapol_key_handshake_type_string(
	const eapol_key_handshake_type_e handshake_type)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_none)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_4_way_handshake)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_group_key_handshake)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_STAKey_handshake)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_802_11i_handshake)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_dynamic_WEP)
#if defined(EAP_USE_WPXM)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_WPXM_reassociation)
#endif //#if defined(EAP_USE_WPXM)
#if defined(USE_WAPI_CORE)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_wai_handshake)
#endif //#if defined(USE_WAPI_CORE)
	else EAP_IF_RETURN_STRING(handshake_type, eapol_key_handshake_type_authenticated)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(handshake_type);

		return EAPL("Unknown EAPOL-Key Handshake type");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eapol_key_state_string_c::get_eapol_key_authentication_type_string(
	const eapol_key_authentication_type_e authentication_type)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_none)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_RSNA_EAP)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_RSNA_PSK)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_WPA_EAP)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_WPA_PSK)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_dynamic_WEP)
#if defined(EAP_USE_WPXM)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_WPXM)
#endif //#if defined(EAP_USE_WPXM)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_WPS)
#if defined(USE_WAPI_CORE)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_WAI_PSK)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_WAI_certificate)
#endif //#if defined(USE_WAPI_CORE)
	else EAP_IF_RETURN_STRING(authentication_type, eapol_key_authentication_type_EAP_authentication_no_encryption)

	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(authentication_type);

		return EAPL("Unknown EAPOL-Key Authentication type");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eapol_key_state_string_c::get_eapol_key_descriptor_type_string(
	const eapol_key_descriptor_type_e key_descriptor_type)
{

#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(key_descriptor_type, eapol_key_descriptor_type_none)
	else EAP_IF_RETURN_STRING(key_descriptor_type, eapol_key_descriptor_type_RC4)
	else EAP_IF_RETURN_STRING(key_descriptor_type, eapol_key_descriptor_type_RSNA)
	else EAP_IF_RETURN_STRING(key_descriptor_type, eapol_key_descriptor_type_WPA)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(key_descriptor_type);

		return EAPL("Unknown EAPOL-Key Description type");
	}
}

//--------------------------------------------------

// End.
