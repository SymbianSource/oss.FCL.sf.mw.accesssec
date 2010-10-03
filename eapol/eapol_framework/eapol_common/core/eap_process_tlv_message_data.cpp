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
* %version: 45 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 40
	#undef EAP_FILE_NUMBER_DATE
	#define EAP_FILE_NUMBER_DATE 1127594498
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_automatic_variable.h"
#include "eap_process_tlv_message_data.h"
#include "eap_variable_data.h"
#include "eap_am_network_id.h"
#include "eap_buffer.h"
#include "eapol_session_key.h"
#include "abs_eap_state_notification.h"
#include "eap_state_notification.h"


/** @file */


//--------------------------------------------------

EAP_FUNC_EXPORT eap_process_tlv_message_data_c::~eap_process_tlv_message_data_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_process_tlv_message_data_c::eap_process_tlv_message_data_c(
	abs_eap_am_tools_c * const tools)
	: eap_tlv_message_data_c(tools)
	, m_am_tools(tools)
	, m_is_valid(true)
{
}

//-------------------------------------------------------------------

/**
 * This function should increase reference count.
 */
EAP_FUNC_EXPORT void eap_process_tlv_message_data_c::object_increase_reference_count()
{
}

//-------------------------------------------------------------------

/**
 * This function should first decrease reference count
 * and second return the remaining reference count.
 * Reference count must not be decreased when it is zero.
 */
EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::object_decrease_reference_count()
{
	return 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_process_tlv_message_data_c::get_is_valid()
{
	return m_is_valid && eap_tlv_message_data_c::get_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const eap_variable_data_c * const data) const
{
	return
		(eap_tlv_header_c::get_header_length() // Each attribute have their own header.
		+ data->get_data_length());
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const eap_am_network_id_c * const network_id) const
{
	if (network_id == 0
		|| network_id->get_is_valid_data() == false)
	{
		return 0ul;
	}

	return
		(3ul * eap_tlv_header_c::get_header_length() // Each attribute have their own header.
		+ network_id->get_source_id()->get_data_length()
		+ network_id->get_destination_id()->get_data_length()
		+ sizeof(network_id->get_type()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const abs_eap_state_notification_c * const state) const
{
	return
		(7ul * eap_tlv_header_c::get_header_length()) // Each attribute have their own header.
		+ (get_payload_size(state->get_send_network_id())
		+ sizeof(u32_t) // eap_protocol_layer_e
		+ sizeof(state->get_protocol())
		+ eap_expanded_type_c::get_eap_expanded_type_size()
		+ sizeof(state->get_current_state())
		+ sizeof(u32_t) // bool is_client
		+ sizeof(u32_t) // eap_status_e authentication error
		);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const eapol_session_key_c * const session_key) const
{
	return
		((5ul * eap_tlv_header_c::get_header_length()) // Each attribute have their own header.
		+ session_key->get_key()->get_data_length()
		+ session_key->get_sequence_number()->get_data_length()
		+ sizeof(u32_t) // const eapol_key_type_e m_key_type
		+ sizeof(session_key->get_key_index())
		+ sizeof(u32_t) // const bool m_key_tx_bit
		);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	EAP_TEMPLATE_CONST eap_array_c<u16_t> * const ushort_array) const
{
	u32_t size(0ul);

	for (u32_t ind = 0ul; ind < ushort_array->get_object_count(); ind++)
	{
		u16_t * const value = ushort_array->get_object(ind);
		if (value != 0)
		{
			size += eap_tlv_header_c::get_header_length() // TLV-header of u16_t.
				+ sizeof(u16_t); // Size of u16_t
		}
	} // for ()

	return (size);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const eap_certificate_entry_c * const cert) const
{
	u32_t size =
		(10ul * eap_tlv_header_c::get_header_length() // Each attribute have their own header.
		+ sizeof(u32_t) // eap_certificate_type_e m_CertType
		+ sizeof(u32_t) // bool m_SubjectNamePresent
		+ sizeof(u32_t) // bool m_IssuerNamePresent
		+ sizeof(u32_t) // bool m_SerialNumberPresent
		+ sizeof(u32_t) // bool m_SubjectKeyIDPresent
		+ sizeof(u32_t) // bool m_ThumbprintPresent
		+ sizeof(u32_t) // bool m_LabelPresent
		+ sizeof(u32_t) // bool m_PrimaryNamePresent
		+ sizeof(u32_t) // bool m_SecondaryNamePresent
		+ sizeof(u32_t) // bool m_iIsEnabledPresent
		);

	if (cert->m_SubjectNamePresent == true)
	{
		size += get_payload_size(&(cert->m_SubjectName));
	}

	if (cert->m_IssuerNamePresent == true)
	{
		size += get_payload_size(&(cert->m_IssuerName));
	}

	if (cert->m_SerialNumberPresent == true)
	{
		size += get_payload_size(&(cert->m_SerialNumber));
	}

	if (cert->m_SubjectKeyIDPresent == true)
	{
		size += get_payload_size(&(cert->m_SubjectKeyID));
	}

	if (cert->m_ThumbprintPresent == true)
	{
		size += get_payload_size(&(cert->m_Thumbprint));
	}

	if (cert->m_LabelPresent == true)
	{
		size += get_payload_size(&(cert->m_Label));
	}

	if (cert->m_PrimaryNamePresent == true)
	{
		size += get_payload_size(&(cert->m_PrimaryName));
	}

	if (cert->m_SecondaryNamePresent == true)
	{
		size += get_payload_size(&(cert->m_SecondaryName));
	}

	if (cert->m_iIsEnabledPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_iIsEnabled
	}

	return size;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const eap_method_settings_c * const internal_settings) const
{
	u32_t size =
		(4ul * eap_tlv_header_c::get_header_length() // Each attribute have their own header.
		+ sizeof(u32_t) // eap_status_e m_completion_status
		+ eap_expanded_type_c::get_eap_expanded_type_size() // eap_type_value_e m_EAPType
		+ sizeof(u32_t) // u32_t m_IndexType
		+ sizeof(u32_t) // u32_t m_Index
		);

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_UseAutomaticCACertificatePresent
	if (internal_settings->m_UseAutomaticCACertificatePresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_UseAutomaticCACertificate
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_UseAutomaticUsernamePresent
	if (internal_settings->m_UseAutomaticUsernamePresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_UseAutomaticUsername
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_UseAutomaticRealmPresent
	if (internal_settings->m_UseAutomaticRealmPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_UseAutomaticRealm
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_UsernamePresent
	if (internal_settings->m_UsernamePresent == true)
	{
		size += get_payload_size(&(internal_settings->m_Username_fix));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_PasswordExistPresent
	if (internal_settings->m_PasswordExistPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_PasswordExist
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_PasswordPresent
	if (internal_settings->m_PasswordPresent == true)
	{
		size += get_payload_size(&(internal_settings->m_Password));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_RealmPresent
	if (internal_settings->m_RealmPresent == true)
	{
		size += get_payload_size(&(internal_settings->m_Realm));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_UsePseudonymsPresent
	if (internal_settings->m_UsePseudonymsPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_UsePseudonyms
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_VerifyServerRealmPresent
	if (internal_settings->m_VerifyServerRealmPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_VerifyServerRealm
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_RequireClientAuthenticationPresent
	if (internal_settings->m_RequireClientAuthenticationPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_RequireClientAuthentication
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_SessionValidityTimePresent
	if (internal_settings->m_SessionValidityTimePresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // u32_t m_SessionValidityTime
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_CipherSuitesPresent
	if (internal_settings->m_CipherSuitesPresent == true)
	{
		// Array header.
		size += eap_tlv_header_c::get_header_length();
		size += get_payload_size(&(internal_settings->m_CipherSuites));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_PEAPVersionsPresent
	if (internal_settings->m_PEAPVersionsPresent == true)
	{
		size += (3ul * eap_tlv_header_c::get_header_length());
		size += sizeof(u32_t); // bool m_PEAPv0Allowed
		size += sizeof(u32_t); // bool m_PEAPv1Allowed
		size += sizeof(u32_t); // bool m_PEAPv2Allowed
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_CertificatesPresent
	if (internal_settings->m_CertificatesPresent == true)
	{
		// Array header.
		size += eap_tlv_header_c::get_header_length();
		size += get_payload_size(&(internal_settings->m_Certificates));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_EnabledEncapsulatedEAPTypesPresent
	if (internal_settings->m_EnabledEncapsulatedEAPTypesPresent == true)
	{
		// Array header.
		size += eap_tlv_header_c::get_header_length();
		size += get_payload_size(&(internal_settings->m_EnabledEncapsulatedEAPTypes));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_DisabledEncapsulatedEAPTypesPresent
	if (internal_settings->m_DisabledEncapsulatedEAPTypesPresent == true)
	{
		// Array header.
		size += eap_tlv_header_c::get_header_length();
		size += get_payload_size(&(internal_settings->m_DisabledEncapsulatedEAPTypes));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_AuthProvModeAllowedPresent
	if (internal_settings->m_AuthProvModeAllowedPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_AuthProvModeAllowed
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_UnauthProvModeAllowedPresent
	if (internal_settings->m_UnauthProvModeAllowedPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_UnauthProvModeAllowed
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_PACGroupReferencePresent
	if (internal_settings->m_PACGroupReferencePresent == true)
	{
		size += get_payload_size(&(internal_settings->m_PACGroupReference));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_WarnADHPNoPACPresent
	if (internal_settings->m_WarnADHPNoPACPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_WarnADHPNoPAC
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_WarnADHPNoMatchingPACPresent
	if (internal_settings->m_WarnADHPNoMatchingPACPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_WarnADHPNoMatchingPAC
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_WarnNotDefaultServerPresent
	if (internal_settings->m_WarnNotDefaultServerPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_WarnNotDefaultServer
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_SelectedEAPTypesPresent
	if (internal_settings->m_SelectedEAPTypesPresent == true)
	{
		// Array header.
		size += eap_tlv_header_c::get_header_length();
		size += get_payload_size(&(internal_settings->m_active_eap_methods));

		// Array header.
		size += eap_tlv_header_c::get_header_length();
		size += get_payload_size(&(internal_settings->m_disabled_eap_methods));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_TunnelingTypePresent
	if (internal_settings->m_TunnelingTypePresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += eap_expanded_type_c::get_eap_expanded_type_size(); // eap_type_value_e m_TunnelingType
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_DestinationIndexAndTypePresent
	if (internal_settings->m_DestinationIndexAndTypePresent == true)
	{
		size += (2ul * eap_tlv_header_c::get_header_length());
		size += sizeof(u32_t); // u32_t m_DestinationIndexType
		size += sizeof(u32_t); // u32_t m_DestinationIndex
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_MethodInfoPresent
	if (internal_settings->m_MethodInfoPresent == true)
	{
		size += get_payload_size(&(internal_settings->m_KReleaseDate));
		size += get_payload_size(&(internal_settings->m_KEapTypeVersion));
		size += get_payload_size(&(internal_settings->m_KManufacturer));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_ButtonIdPresent
	if (internal_settings->m_ButtonIdPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // i32_t m_ButtonId
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_ShowPassWordPromptPresent
	if (internal_settings->m_ShowPassWordPromptPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_ShowPassWordPrompt));
	}

	size += eap_tlv_header_c::get_header_length();
	size += sizeof(u32_t); // bool m_UseIdentityPrivacyPresent
	if (internal_settings->m_UseIdentityPrivacyPresent == true)
	{
		size += eap_tlv_header_c::get_header_length();
		size += sizeof(u32_t); // bool m_UseIdentityPrivacy));
	}

	return size;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	EAP_TEMPLATE_CONST eap_array_c<eap_certificate_entry_c> * const cert_array) const
{
	u32_t size(0ul);

	for (u32_t ind = 0ul; ind < cert_array->get_object_count(); ind++)
	{
		eap_certificate_entry_c * const value = cert_array->get_object(ind);
		if (value != 0)
		{
			// Structure header.
			size += eap_tlv_header_c::get_header_length();

			size += get_payload_size(value);
		}
	} // for ()

	return (size);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const network_key_and_index_c * const key) const
{
	u32_t size(0ul);

	if (key != 0)
	{
		size += eap_tlv_header_c::get_header_length()
			+ sizeof(key->get_network_key_index()) // Size of Network Key Index
			+ eap_tlv_header_c::get_header_length()
			+ key->get_network_key_const()->get_data_length() // Size of Network Key
			;
	}

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const eap_array_c<network_key_and_index_c> * const network_keys) const
{
	u32_t size(0ul);

	for (u32_t ind_network_key = 0ul; ind_network_key < network_keys->get_object_count(); ind_network_key++)
	{
		network_key_and_index_c * const key = network_keys->get_object(ind_network_key);
		if (key != 0)
		{
			size += eap_tlv_header_c::get_header_length() // Size of structure header
				+ get_payload_size(key); // Size of Network Key
		}
	} // for ()

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const simple_config_credential_c * const credential) const
{
	u32_t size(0ul);

	if (credential != 0)
	{
		size += eap_tlv_header_c::get_header_length()
			+ sizeof(credential->get_network_index()) // Size of Network Index
			+ eap_tlv_header_c::get_header_length()
			+ credential->get_SSID_const()->get_data_length() // Size of SSID
			+ eap_tlv_header_c::get_header_length()
			+ sizeof(u16_t) // Size of Authentiction type
			+ eap_tlv_header_c::get_header_length()
			+ sizeof(u16_t) // Size of Encryption type
			;

		size += eap_tlv_header_c::get_header_length() // Size of header of Array
			+ get_payload_size(credential->get_network_keys_const());

		size += eap_tlv_header_c::get_header_length()
			+ credential->get_MAC_address_const()->get_data_length() // Size of MAC Address
			;
	}

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array) const
{
	u32_t size(0ul);

	for (u32_t ind_credential = 0ul; ind_credential < credential_array->get_object_count(); ind_credential++)
	{
		simple_config_credential_c * const credential = credential_array->get_object(ind_credential);
		if (credential != 0)
		{
			size += eap_tlv_header_c::get_header_length() // Size of structure header
				+ get_payload_size(credential);
		}
	} // for ()

	return (size);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	const eap_variable_data_c * const selector,
	const eap_config_value_c * const configuration_option) const
{
	u32_t size_of_data(0ul);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_payload_size(): type=%d=%s\n"),
		configuration_option->get_const_type(),
		eap_configuration_field_c::get_configure_type_string(configuration_option->get_const_type())));

	switch(configuration_option->get_const_type())
	{
	case eap_configure_type_string:
	case eap_configure_type_hex_data:
		size_of_data += 3ul * eap_tlv_header_c::get_header_length()
			+ sizeof(u32_t) // Length of the type.
			+ selector->get_data_length() // Length of the option name.
			+ configuration_option->get_const_data()->get_data_length(); // Length of the option data.
		break;
	case eap_configure_type_u32_t:
	case eap_configure_type_boolean:
		size_of_data += 3ul * eap_tlv_header_c::get_header_length()
			+ sizeof(u32_t) // Length of the type.
			+ selector->get_data_length() // Length of the option name.
			+ sizeof(u32_t); // Length of the option data.
		break;
	case eap_configure_type_u32array:
		{
			const u32_t count_of_values = configuration_option->get_const_data()->get_data_length() / sizeof(u32_t);
			size_of_data += 3ul * eap_tlv_header_c::get_header_length()
				+ sizeof(u32_t) // Length of the type.
				+ selector->get_data_length() // Length of the option name.
				+ count_of_values*(eap_tlv_header_c::get_header_length()+sizeof(u32_t)); // Length of the option data.
		}
		break;
	case eap_configure_type_subsection:
		// No size.
		break;
	default:
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("ERROR: eap_process_tlv_message_data_c::get_payload_size(): Unknown type=%d=%s\n"),
			configuration_option->get_const_type(),
			eap_configuration_field_c::get_configure_type_string(configuration_option->get_const_type())));
		break;
	};

	return (size_of_data);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_structured_parameter_header(
	const eap_tlv_message_type_e type,
	const u32_t length)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_structured_parameter_header(): type=%d=%s\n"),
		type,
		 get_type_string(type)));

	return add_message_header(
		type,
		length);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_tlv_message_type_e type,
	const u32_t integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		type,
		 get_type_string(type)));

	const u32_t network_order_integer(eap_htonl(integer));

	eap_status_e status = add_message_data(
		type,
		sizeof(network_order_integer),
		&network_order_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const u64_t long_integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_u64_t,
		 get_type_string(eap_tlv_message_type_u64_t)));

	const u64_t network_order_long_integer(eap_htonll(long_integer));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_u64_t,
		sizeof(network_order_long_integer),
		&network_order_long_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const u32_t integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_u32_t,
		 get_type_string(eap_tlv_message_type_u32_t)));

	const u32_t network_order_integer(eap_htonl(integer));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_u32_t,
		sizeof(network_order_integer),
		&network_order_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const u16_t short_integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_u16_t,
		 get_type_string(eap_tlv_message_type_u16_t)));

	const u16_t network_order_short_integer(eap_htons(short_integer));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_u16_t,
		sizeof(network_order_short_integer),
		&network_order_short_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const u8_t byte_integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_u8_t,
		 get_type_string(eap_tlv_message_type_u8_t)));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_u8_t,
		sizeof(byte_integer),
		&byte_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const i32_t integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_i32_t,
		 get_type_string(eap_tlv_message_type_i32_t)));

	const i32_t network_order_integer(eap_htonl(integer));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_i32_t,
		sizeof(network_order_integer),
		&network_order_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const i16_t integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_i16_t,
		 get_type_string(eap_tlv_message_type_i16_t)));

	const i16_t network_order_short_integer(eap_htons(integer));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_i16_t,
		sizeof(network_order_short_integer),
		&network_order_short_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const i8_t byte_integer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_i8_t,
		 get_type_string(eap_tlv_message_type_i8_t)));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_i8_t,
		sizeof(byte_integer),
		&byte_integer);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const bool boolean)
{
	const u32_t value((boolean == false) ? 0u: 1u);

	return add_parameter_data(
		eap_tlv_message_type_boolean,
		value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_status_e status)
{
	const u32_t value(static_cast<u32_t>(status));

	return add_parameter_data(
		eap_tlv_message_type_eap_status,
		value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eapol_key_authentication_type_e authentication_type)
{
	const u32_t value(static_cast<u32_t>(authentication_type));

	return add_parameter_data(
		eap_tlv_message_type_eapol_key_authentication_type,
		value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eapol_key_802_11_authentication_mode_e mode)
{
	const u32_t value(static_cast<u32_t>(mode));

	return add_parameter_data(
		eap_tlv_message_type_eapol_key_802_11_authentication_mode,
		value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_tlv_message_type_function_e function)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, function=%s\n"),
		eap_tlv_message_type_function,
		 get_type_string(eap_tlv_message_type_function),
		 get_function_string(function)));

	if (function < eap_tlv_message_type_function_none
		|| function >= eap_tlv_message_type_function_illegal_value)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t network_order_function(eap_htonl(function));

	eap_status_e status = add_message_data(
		eap_tlv_message_type_function,
		sizeof(network_order_function),
		&network_order_function);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_variable_data_c * const variable_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_variable_data,
		 get_type_string(eap_tlv_message_type_variable_data)));

	if (variable_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_process_general_error);

	if (variable_data->get_is_valid_data() == false)
	{
		// Empty variable data. Add just the header.
		status = add_structured_parameter_header(
			eap_tlv_message_type_variable_data,
			0ul);
	}
	else
	{
		status = add_message_data(
			eap_tlv_message_type_variable_data,
			variable_data->get_data_length(),
			variable_data->get_data());
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_am_network_id_c * const network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_network_id,
		 get_type_string(eap_tlv_message_type_network_id)));

	if (network_id == 0
		|| network_id->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_network_id = get_payload_size(network_id);

	eap_status_e status = add_structured_parameter_header(
		eap_tlv_message_type_network_id,
		size_of_network_id);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		network_id->get_source_id());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		network_id->get_destination_id());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		network_id->get_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_buf_chain_wr_c * const packet_buffer)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_variable_data,
		 get_type_string(eap_tlv_message_type_variable_data)));

	if (packet_buffer == 0
		|| packet_buffer->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = add_message_data(
		eap_tlv_message_type_variable_data,
		packet_buffer->get_data_length(),
		packet_buffer->get_data(packet_buffer->get_data_length()));


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eapol_session_key_c * const session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_session_key,
		 get_type_string(eap_tlv_message_type_session_key)));

	if (session_key == 0
		|| session_key->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_session_key(get_payload_size(session_key));

	eap_status_e status = add_structured_parameter_header(
		eap_tlv_message_type_session_key,
		size_of_session_key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		session_key->get_key());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		session_key->get_sequence_number());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		eap_tlv_message_type_eapol_key_type,
		static_cast<u32_t>(session_key->get_key_type()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(session_key->get_key_index());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(session_key->get_key_tx_bit());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const abs_eap_state_notification_c * const state)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_eap_state_notification,
		 get_type_string(eap_tlv_message_type_eap_state_notification)));

	if (state == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_state(get_payload_size(state));

	eap_status_e status = add_structured_parameter_header(
		eap_tlv_message_type_eap_state_notification,
		size_of_state);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_send_network_id());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(
		eap_tlv_message_type_eap_protocol_layer,
		static_cast<u32_t>(state->get_protocol_layer()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_protocol());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_eap_type());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_current_state());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_is_client());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = add_parameter_data(state->get_authentication_error());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_type_value_e eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_eap_type,
		 get_type_string(eap_tlv_message_type_eap_type)));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("add_parameter_data(eap_type_value_e)"),
		 &eap_type,
		 sizeof(eap_type)));

	void * type_buffer = 0;

	eap_status_e status = allocate_message_buffer(
		eap_tlv_message_type_eap_type,
		eap_expanded_type_c::get_eap_expanded_type_size(),
		&type_buffer);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = eap_expanded_type_c::write_type(
		m_am_tools,
		0ul, ///< Index is from 0 to n. Index 0 is the first EAP type field after base EAP header.
		type_buffer,
		eap_expanded_type_c::get_eap_expanded_type_size(),
		true, ///< True value writes always Extented Type.
		eap_type ///< The EAP type to be written.
		);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_tlv_message_data_c::add_message_data():   type %2d=0x%08x, length %3d=0x%08x\n"),
		 eap_tlv_message_type_eap_type,
		 eap_tlv_message_type_eap_type,
		 eap_expanded_type_c::get_eap_expanded_type_size(),
		 eap_expanded_type_c::get_eap_expanded_type_size()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("add_message_data()"),
		type_buffer,
		eap_expanded_type_c::get_eap_expanded_type_size()));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_general_header_base_c * const packet_data,
	const u32_t packet_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_variable_data,
		 get_type_string(eap_tlv_message_type_variable_data)));

	if (packet_data == 0
		|| packet_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (packet_length > packet_data->get_header_buffer_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = add_message_data(
		eap_tlv_message_type_variable_data,
		packet_length,
		packet_data->get_header_buffer(packet_length));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_certificate_entry_c * const certificate_entry)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_eap_certificate_entry,
		 get_type_string(eap_tlv_message_type_eap_certificate_entry)));

	eap_status_e status(eap_status_not_supported);


	const u32_t size_of_certificate(get_payload_size(certificate_entry));

	status = add_structured_parameter_header(
		eap_tlv_message_type_eap_certificate_entry,
		size_of_certificate);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	{
		// Specifies whether this entry describes user or CA certificate (mandatory)
		status = add_parameter_data(static_cast<u32_t>(certificate_entry->m_CertType));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	{
		// Subject name in distinguished name ASCII form. This is optional.
		// For example "/C=US/O=Some organization/CN=Some common name".
		status = add_parameter_data(certificate_entry->m_SubjectNamePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_SubjectNamePresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_SubjectName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// Issuer name in distinguished name ASCII form. This is optional.
		// For example "/C=US/O=Some organization/CN=Some common name".
		status = add_parameter_data(certificate_entry->m_IssuerNamePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_IssuerNamePresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_IssuerName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// Serial number in ASCII form. This is optional.
		status = add_parameter_data(certificate_entry->m_SerialNumberPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_SerialNumberPresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_SerialNumber));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// Subject key in binary form. This is mandatory.
		status = add_parameter_data(certificate_entry->m_SubjectKeyIDPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_SubjectKeyIDPresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_SubjectKeyID));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// Thumbprint in binary form. This is optional.
		status = add_parameter_data(certificate_entry->m_ThumbprintPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_ThumbprintPresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_Thumbprint));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}


	{
		// This holds only the certificate label. This is the text UI will show.
		status = add_parameter_data(certificate_entry->m_LabelPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_LabelPresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_Label));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// Primary name of the certificate if any, UI uses this.
		status = add_parameter_data(certificate_entry->m_PrimaryNamePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_PrimaryNamePresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_PrimaryName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// Secondary name of the certificate if any, UI uses this.
		status = add_parameter_data(certificate_entry->m_SecondaryNamePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_SecondaryNamePresent == true)
		{
			status = add_parameter_data(&(certificate_entry->m_SecondaryName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		// UI uses this to indicate enabled certificate.
		status = add_parameter_data(certificate_entry->m_iIsEnabledPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (certificate_entry->m_iIsEnabledPresent == true)
		{
			status = add_parameter_data((certificate_entry->m_iIsEnabled));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_eap_method_settings,
		 get_type_string(eap_tlv_message_type_eap_method_settings)));

	eap_status_e status(eap_status_not_supported);

	const u32_t size_of_settings(get_payload_size(internal_settings));

	status = add_structured_parameter_header(
		eap_tlv_message_type_eap_method_settings,
		size_of_settings);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_completion_status\n"),
		eap_tlv_message_type_eap_method_settings,
		 get_type_string(eap_tlv_message_type_eap_method_settings)));

	status = add_parameter_data((internal_settings->m_completion_status));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_EAPType\n"),
		eap_tlv_message_type_eap_method_settings,
		 get_type_string(eap_tlv_message_type_eap_method_settings)));

	// Specifies the EAP-method these settings are for.
	status = add_parameter_data(internal_settings->m_EAPType);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_IndexType\n"),
		eap_tlv_message_type_eap_method_settings,
		 get_type_string(eap_tlv_message_type_eap_method_settings)));

	status = add_parameter_data((internal_settings->m_IndexType));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_Index\n"),
		eap_tlv_message_type_eap_method_settings,
		 get_type_string(eap_tlv_message_type_eap_method_settings)));

	status = add_parameter_data((internal_settings->m_Index));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseAutomaticCACertificatePresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Use automatic CA certificate.
		status = add_parameter_data(internal_settings->m_UseAutomaticCACertificatePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseAutomaticCACertificatePresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseAutomaticCACertificate\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_UseAutomaticCACertificate));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseAutomaticUsernamePresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Use automatic username.
		status = add_parameter_data(internal_settings->m_UseAutomaticUsernamePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseAutomaticUsernamePresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseAutomaticUsername\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_UseAutomaticUsername));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseAutomaticRealmPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Use automatic username.
		status = add_parameter_data(internal_settings->m_UseAutomaticRealmPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseAutomaticRealmPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseAutomaticRealm\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_UseAutomaticRealm));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UsernamePresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Username in ASCII format
		status = add_parameter_data(internal_settings->m_UsernamePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UsernamePresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_Username_fix\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_Username_fix));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PasswordExistPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Password existence
		status = add_parameter_data(internal_settings->m_PasswordExistPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PasswordExistPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PasswordExist\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(internal_settings->m_PasswordExist);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PasswordPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Password in ASCII format
		status = add_parameter_data(internal_settings->m_PasswordPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PasswordPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_Password\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_Password));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_RealmPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Realm in ASCII format
		status = add_parameter_data(internal_settings->m_RealmPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_RealmPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_Realm\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_Realm));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UsePseudonymsPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Use pseudonym identities in EAP-SIM/AKA
		status = add_parameter_data(internal_settings->m_UsePseudonymsPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UsePseudonymsPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UsePseudonyms\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_UsePseudonyms));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_VerifyServerRealmPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether EAP-TLS/TTLS/PEAP should verify server realm
		status = add_parameter_data(internal_settings->m_VerifyServerRealmPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_VerifyServerRealmPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_VerifyServerRealm\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_VerifyServerRealm));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_RequireClientAuthenticationPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether EAP-TLS/TTLS/PEAP should require client authentication
		status = add_parameter_data(internal_settings->m_RequireClientAuthenticationPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_RequireClientAuthenticationPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_RequireClientAuthentication\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_RequireClientAuthentication));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_SessionValidityTimePresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// General session validity time (in minutes)
		status = add_parameter_data(internal_settings->m_SessionValidityTimePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_SessionValidityTimePresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_SessionValidityTime\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_SessionValidityTime));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_CipherSuitesPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// An array of allowed cipher suites for EAP-TLS/TTLS/PEAP.
		// Refer to RFC2246 chapter A.5 for the values.
		status = add_parameter_data(internal_settings->m_CipherSuitesPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_CipherSuitesPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_CipherSuites\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_CipherSuites));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PEAPVersionsPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Which EAP-PEAP versions are allowed
		status = add_parameter_data(internal_settings->m_PEAPVersionsPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PEAPVersionsPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PEAPv0Allowed\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_PEAPv0Allowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PEAPv1Allowed\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_PEAPv1Allowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PEAPv2Allowed\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_PEAPv2Allowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_CertificatesPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

  		// Array listing the allowed certificates for EAP-TLS/TTLS/PEAP.
  		// Subject key ID and Certificate type are the only mandatory certificate
  		// details needed at the moment.
		status = add_parameter_data(internal_settings->m_CertificatesPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_CertificatesPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_Certificates\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_Certificates));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_EnabledEncapsulatedEAPTypesPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Array listing the enabled encapsulated EAP types (in priority order).
		// Use EAP type values from eap_type_value_e.
		status = add_parameter_data(internal_settings->m_EnabledEncapsulatedEAPTypesPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_EnabledEncapsulatedEAPTypesPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_EnabledEncapsulatedEAPTypes\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_EnabledEncapsulatedEAPTypes));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_DisabledEncapsulatedEAPTypesPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Array listing the disabled encapsulated EAP types (in priority order).
		// Use EAP type values from eap_type_value_e.
		status = add_parameter_data(internal_settings->m_DisabledEncapsulatedEAPTypesPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_DisabledEncapsulatedEAPTypesPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_DisabledEncapsulatedEAPTypes\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_DisabledEncapsulatedEAPTypes));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_AuthProvModeAllowedPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether Authenticated provisioning mode allowed or not in EAP-FAST.
		status = add_parameter_data(internal_settings->m_AuthProvModeAllowedPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_AuthProvModeAllowedPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_AuthProvModeAllowed\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_AuthProvModeAllowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UnauthProvModeAllowedPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether Unauthenticated provisioning mode allowed or not in EAP-FAST.
		status = add_parameter_data(internal_settings->m_UnauthProvModeAllowedPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UnauthProvModeAllowedPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UnauthProvModeAllowed\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_UnauthProvModeAllowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PACGroupReferencePresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// PAC group reference in ASCII format for EAP-FAST.
		status = add_parameter_data(internal_settings->m_PACGroupReferencePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PACGroupReferencePresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_PACGroupReference\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_PACGroupReference));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_WarnADHPNoPACPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether to Warn (or Prompt) for ADHP (Authenticated Diffie-Hellman Protocol)
		// auto-provisioning when there is no PAC at all. EAP-FAST specific.
		status = add_parameter_data(internal_settings->m_WarnADHPNoPACPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_WarnADHPNoPACPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_WarnADHPNoPAC\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_WarnADHPNoPAC));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_WarnADHPNoMatchingPACPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether to Warn (or Prompt) for ADHP auto-provisioning when
		// there is no PAC that matches the A-ID sent by server. EAP-FAST specific.
		status = add_parameter_data(internal_settings->m_WarnADHPNoMatchingPACPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_WarnADHPNoMatchingPACPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_WarnADHPNoMatchingPAC\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_WarnADHPNoMatchingPAC));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_WarnNotDefaultServerPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether to Warn (or Prompt) when client encouters a server that has provisioned
		// the client with a PAC before but is not currently selected as the default server.
		// EAP-FAST specific.
		status = add_parameter_data(internal_settings->m_WarnNotDefaultServerPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_WarnNotDefaultServerPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_WarnNotDefaultServer\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_WarnNotDefaultServer));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_SelectedEAPTypesPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Array listing the active and disabled EAP types (in priority order).
		// Use EAP type values from eap_type_value_e.
		status = add_parameter_data(internal_settings->m_SelectedEAPTypesPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_SelectedEAPTypesPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_active_eap_methods\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_active_eap_methods));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_disabled_eap_methods\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_disabled_eap_methods));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_TunnelingTypePresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		status = add_parameter_data(internal_settings->m_TunnelingTypePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_TunnelingTypePresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_TunnelingType\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_TunnelingType));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_DestinationIndexAndTypePresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		status = add_parameter_data(internal_settings->m_DestinationIndexAndTypePresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_DestinationIndexAndTypePresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_DestinationIndexType\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_DestinationIndexType));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_DestinationIndex\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_DestinationIndex));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_MethodInfoPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		status = add_parameter_data(internal_settings->m_MethodInfoPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_MethodInfoPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_KReleaseDate\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_KReleaseDate));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_KEapTypeVersion\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_KEapTypeVersion));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_KManufacturer\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data(&(internal_settings->m_KManufacturer));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_ButtonIdPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		status = add_parameter_data(internal_settings->m_ButtonIdPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_ButtonIdPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_ButtonId\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_ButtonId));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}


	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_ShowPassWordPromptPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether to show (or Prompt) password.
		status = add_parameter_data(internal_settings->m_ShowPassWordPromptPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_ShowPassWordPromptPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_ShowPassWordPrompt\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_ShowPassWordPrompt));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}


	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseIdentityPrivacyPresent\n"),
			eap_tlv_message_type_eap_method_settings,
			 get_type_string(eap_tlv_message_type_eap_method_settings)));

		// Whether to show (or Prompt) password.
		status = add_parameter_data(internal_settings->m_UseIdentityPrivacyPresent);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseIdentityPrivacyPresent == true)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s, m_UseIdentityPrivacy\n"),
				eap_tlv_message_type_eap_method_settings,
				 get_type_string(eap_tlv_message_type_eap_method_settings)));

			status = add_parameter_data((internal_settings->m_UseIdentityPrivacy));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}


	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<u16_t> * const ushort_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): array type=%d=%s\n"),
		eap_tlv_message_type_u16_t,
		 get_type_string(eap_tlv_message_type_u16_t)));

	if (ushort_array == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_ushort_array(get_payload_size(ushort_array));

	eap_status_e status = add_structured_parameter_header(
		eap_tlv_message_type_array,
		size_of_ushort_array);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind = 0ul; ind < ushort_array->get_object_count(); ind++)
	{
		const u16_t * const value = ushort_array->get_object(ind);
		if (value != 0)
		{
			status = add_parameter_data(*value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_certificate_entry_c> * const cert_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): array type=%d=%s\n"),
		eap_tlv_message_type_eap_certificate_entry,
		 get_type_string(eap_tlv_message_type_eap_certificate_entry)));

	if (cert_array == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_cert_array(get_payload_size(cert_array));

	eap_status_e status = add_structured_parameter_header(
		eap_tlv_message_type_array,
		size_of_cert_array);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind = 0ul; ind < cert_array->get_object_count(); ind++)
	{
		const eap_certificate_entry_c * const value = cert_array->get_object(ind);
		if (value != 0)
		{
			status = add_parameter_data(value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<simple_config_credential_c> * const credential_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): array type=%d=%s\n"),
		eap_tlv_message_type_protected_setup_credential,
		 get_type_string(eap_tlv_message_type_protected_setup_credential)));

	if (credential_array == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u32_t size_of_credential_array(get_payload_size(credential_array));

	eap_status_e status = add_structured_parameter_header(
		eap_tlv_message_type_array,
		size_of_credential_array);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_credential = 0ul; ind_credential < credential_array->get_object_count(); ind_credential++)
	{
		simple_config_credential_c * const credential = credential_array->get_object(ind_credential);
		if (credential != 0)
		{
			const u32_t size_of_credential(get_payload_size(credential));

			eap_status_e status = add_structured_parameter_header(
				eap_tlv_message_type_protected_setup_credential,
				size_of_credential);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(credential->get_network_index());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(credential->get_SSID());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(static_cast<u16_t>(credential->get_Authentication_Type()));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = add_parameter_data(static_cast<u16_t>(credential->get_Encryption_Type()));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			const u32_t size_of_network_key_array(get_payload_size(credential->get_network_keys()));

			status = add_structured_parameter_header(
				eap_tlv_message_type_array,
				size_of_network_key_array);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			for (u32_t ind_network_key = 0ul; ind_network_key < credential->get_network_keys()->get_object_count(); ind_network_key++)
			{
				network_key_and_index_c * const network_key = credential->get_network_keys()->get_object(ind_network_key);
				if (network_key != 0)
				{
					const u32_t size_of_network_key(get_payload_size(network_key));

					status = add_structured_parameter_header(
						eap_tlv_message_type_network_key,
						size_of_network_key);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = add_parameter_data(network_key->get_network_key_index());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					status = add_parameter_data(network_key->get_network_key());
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			} // for ()

			status = add_parameter_data(credential->get_MAC_address());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	const eap_variable_data_c * const selector,
	const eap_config_value_c * const configuration_option)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(): type=%d=%s\n"),
		eap_tlv_message_type_variable_data,
		 get_type_string(eap_tlv_message_type_variable_data)));

	if (selector == 0
		|| selector->get_is_valid_data() == false
		|| configuration_option == 0
		|| configuration_option->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_ok);

	u32_t size_of_data = get_payload_size(
		selector,
		configuration_option);

	if (size_of_data > 0ul)
	{
		status = add_structured_parameter_header(
				eap_tlv_message_type_configuration_option,
				size_of_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = add_parameter_data(static_cast<u32_t>(configuration_option->get_const_type()));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = add_parameter_data(selector);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}


		switch(configuration_option->get_const_type())
		{
		case eap_configure_type_string:
		case eap_configure_type_hex_data:
			status = add_parameter_data(configuration_option->get_const_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			break;
		case eap_configure_type_u32_t:
		case eap_configure_type_boolean:
			{
				const u32_t * value = reinterpret_cast<const u32_t *>(configuration_option->get_const_data()->get_data(sizeof(u32_t)));
				if (value != 0)
				{
					status = add_parameter_data(*value);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
			}
			break;
		case eap_configure_type_u32array:
			{
				const u32_t count_of_values = configuration_option->get_const_data()->get_data_length() / sizeof(u32_t);
				const u32_t * value = reinterpret_cast<const u32_t *>(configuration_option->get_const_data()->get_data(sizeof(u32_t)));
				if (value != 0)
				{
					status = add_structured_parameter_header(
							eap_tlv_message_type_array,
							count_of_values*(eap_tlv_header_c::get_header_length()+sizeof(u32_t)));
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					for (u32_t ind = 0ul; ind < count_of_values; ++ind)
					{
						status = add_parameter_data(value[ind]);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}
				}
			}
			break;
		default:
			break;
		};
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u64_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		integer_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u64_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(integer_header->get_type())
		!= eap_tlv_message_type_u64_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u64_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value =
		eap_read_u64_t_network_order(
			data,
			sizeof(u64_t));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u32_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		integer_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u32_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_boolean
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_eap_protocol_layer
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_eapol_key_802_11_authentication_mode
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_eapol_key_authentication_type
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_eapol_key_type
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_eapol_tkip_mic_failure_type
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_eapol_wlan_authentication_state
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_error
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_function
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_RSNA_cipher
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_u32_t
		&& static_cast<eap_tlv_message_type_e>(integer_header->get_type())
			!= eap_tlv_message_type_eap_status
			)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u32_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value =
		eap_read_u32_t_network_order(
			data,
			sizeof(u32_t));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u16_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		integer_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u16_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(integer_header->get_type())
		!= eap_tlv_message_type_u16_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u16_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value =
		eap_read_u16_t_network_order(
			data,
			sizeof(u16_t));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	u8_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		integer_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u8_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(integer_header->get_type())
		!= eap_tlv_message_type_u8_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(u8_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value = *data;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	i32_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		integer_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u8_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(integer_header->get_type())
		!= eap_tlv_message_type_i32_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(i32_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value = static_cast<i32_t>(eap_read_u32_t_network_order(
			data,
			sizeof(i32_t)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	i16_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		integer_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u8_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(integer_header->get_type())
		!= eap_tlv_message_type_i16_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(i16_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value = static_cast<i16_t>(eap_read_u16_t_network_order(
			data,
			sizeof(i16_t)));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const integer_header,
	i8_t * const value)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		integer_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(integer_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(u8_t *)"),
		integer_header->get_header_buffer(integer_header->get_header_buffer_length()),
		integer_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(integer_header->get_type())
		!= eap_tlv_message_type_i8_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	const u8_t * const data = integer_header->get_value(sizeof(i8_t));
	if (data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*value = static_cast<i8_t>(*data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const function_header,
	eap_tlv_message_type_function_e * const function)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		function_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(function_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_tlv_message_type_function_e *)"),
		function_header->get_header_buffer(function_header->get_header_buffer_length()),
		function_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(function_header->get_type())
		!= eap_tlv_message_type_function)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	u32_t host_order(0ul);

	eap_status_e status = get_parameter_data(
		function_header,
		&host_order);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	*function = static_cast<eap_tlv_message_type_function_e>(host_order);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, function=%s\n"),
		eap_tlv_message_type_function,
		 get_type_string(eap_tlv_message_type_function),
		 get_function_string(*function)
		 ));

	if (*function < eap_tlv_message_type_function_none
		|| eap_tlv_message_type_function_illegal_value <= *function)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const network_id_header,
	eap_am_network_id_c * const new_network_id)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		network_id_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(network_id_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_am_network_id_c *)"),
		network_id_header->get_header_buffer(network_id_header->get_header_buffer_length()),
		network_id_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(network_id_header->get_type())
		!= eap_tlv_message_type_network_id)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c network_id_data(m_am_tools);

	if (network_id_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = network_id_data.set_message_data(
		network_id_header->get_value_length(),
		network_id_header->get_value(network_id_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> network_id_members(m_am_tools);

	status = network_id_data.parse_message_data(&network_id_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t member_index(0ul);

	eap_variable_data_c source_id(
		m_am_tools);

	if (source_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		const eap_tlv_header_c * const source_id_header = network_id_members.get_object(member_index);
		if (source_id_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = network_id_data.get_parameter_data(source_id_header, &source_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	eap_variable_data_c destination_id(
		m_am_tools);

	if (destination_id.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		const eap_tlv_header_c * const destination_id_header = network_id_members.get_object(member_index);
		if (destination_id_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = network_id_data.get_parameter_data(destination_id_header, &destination_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	u16_t type_value(0ul);

	{
		const eap_tlv_header_c * const type_header = network_id_members.get_object(member_index);
		if (type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = network_id_data.get_parameter_data(type_header, &type_value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	status = new_network_id->set_copy_of_am_network_id(
		source_id.get_data(),
		source_id.get_data_length(),
		destination_id.get_data(),
		destination_id.get_data_length(),
		type_value);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const variable_data_header,
	eap_variable_data_c * const variable_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		variable_data_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(variable_data_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_variable_data_c *)"),
		variable_data_header->get_header_buffer(variable_data_header->get_header_buffer_length()),
		variable_data_header->get_header_buffer_length()));

	if (variable_data == 0
		|| variable_data->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (static_cast<eap_tlv_message_type_e>(variable_data_header->get_type())
		!= eap_tlv_message_type_variable_data)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_status_e status = variable_data->set_copy_of_buffer(
		variable_data_header->get_value(variable_data_header->get_value_length()),
		variable_data_header->get_value_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const session_key_header,
		eapol_session_key_c * const session_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		session_key_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(session_key_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eapol_session_key_c *)"),
		session_key_header->get_header_buffer(session_key_header->get_header_buffer_length()),
		session_key_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(session_key_header->get_type())
		!= eap_tlv_message_type_session_key)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c session_key_data(m_am_tools);

	if (session_key_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = session_key_data.set_message_data(
		session_key_header->get_value_length(),
		session_key_header->get_value(session_key_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> session_key_members(m_am_tools);

	status = session_key_data.parse_message_data(&session_key_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	{
		const eap_tlv_header_c * const a_session_key_header = session_key_members.get_object(member_index);
		if (a_session_key_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eap_variable_data_c key(
			m_am_tools);

		if (key.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = session_key_data.get_parameter_data(a_session_key_header, &key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = session_key->set_key(&key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	{
		const eap_tlv_header_c * const sequence_number_header = session_key_members.get_object(member_index);
		if (sequence_number_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eap_variable_data_c sequence_number(
			m_am_tools);

		if (sequence_number.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = session_key_data.get_parameter_data(sequence_number_header, &sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = session_key->set_sequence_number(&sequence_number);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	{
		const eap_tlv_header_c * const key_type_header = session_key_members.get_object(member_index);
		if (key_type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(key_type_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		session_key->set_key_type(static_cast<eapol_key_type_e>(value));
	}

	++member_index;

	{
		const eap_tlv_header_c * const key_index_header = session_key_members.get_object(member_index);
		if (key_index_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(key_index_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		session_key->set_key_index(value);
	}

	++member_index;

	{
		const eap_tlv_header_c * const key_tx_bit_header = session_key_members.get_object(member_index);
		if (key_tx_bit_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(key_tx_bit_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		session_key->set_key_tx_bit((value == 0) ? false : true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const state_header,
	eap_state_notification_c * * const state)

{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		state_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(state_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_state_notification_c *)"),
		state_header->get_header_buffer(state_header->get_header_buffer_length()),
		state_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(state_header->get_type())
		!= eap_tlv_message_type_eap_state_notification)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c session_key_data(m_am_tools);

	if (session_key_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = session_key_data.set_message_data(
		state_header->get_value_length(),
		state_header->get_value(state_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> session_key_members(m_am_tools);

	status = session_key_data.parse_message_data(&session_key_members);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t member_index(0ul);

	eap_am_network_id_c send_network_id(m_am_tools);

	{
		const eap_tlv_header_c * const send_network_id_header = session_key_members.get_object(member_index);
		if (send_network_id_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = get_parameter_data(send_network_id_header, &send_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	eap_protocol_layer_e protocol_layer(eap_protocol_layer_none);

	{
		const eap_tlv_header_c * const protocol_layer_header = session_key_members.get_object(member_index);
		if (protocol_layer_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(protocol_layer_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		protocol_layer = static_cast<eap_protocol_layer_e>(value);
	}


	++member_index;

	u32_t protocol(0ul);

	{
		const eap_tlv_header_c * const protocol_header = session_key_members.get_object(member_index);
		if (protocol_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = session_key_data.get_parameter_data(protocol_header, &protocol);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	eap_type_value_e eap_type(eap_type_none);

	{
		const eap_tlv_header_c * const eap_type_header = session_key_members.get_object(member_index);
		if (eap_type_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = session_key_data.get_parameter_data(eap_type_header, &eap_type);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	u32_t current_state(0ul);

	{
		const eap_tlv_header_c * const current_state_header = session_key_members.get_object(member_index);
		if (current_state_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = session_key_data.get_parameter_data(current_state_header, &current_state);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}


	++member_index;

	bool is_client(true);

	{
		const eap_tlv_header_c * const is_client_header = session_key_members.get_object(member_index);
		if (is_client_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(is_client_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		is_client = (value == 0ul) ? false : true;
	}


	++member_index;

	eap_status_e authentication_error(eap_status_ok);

	{
		const eap_tlv_header_c * const authentication_error_header = session_key_members.get_object(member_index);
		if (authentication_error_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		u32_t value(0ul);

		status = session_key_data.get_parameter_data(authentication_error_header, &value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		authentication_error = static_cast<eap_status_e>(value);
	}

	if (eap_type != eap_type_none)
	{
		*state = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			is_client,
			eap_state_notification_eap,
			protocol_layer,
			eap_type,
			current_state,
			current_state,
			0ul,
			false);
	}
	else
	{


		*state = new eap_state_notification_c(
			m_am_tools,
			&send_network_id,
			is_client,
			eap_state_notification_generic,
			protocol_layer,
			protocol,
			current_state,
			current_state,
			0ul,
			false);
	}

	if ((*state) == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	(*state)->set_authentication_error(authentication_error);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const eap_type_header,
	eap_type_value_e * const eap_type)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		eap_type_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(eap_type_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_type_value_e *)"),
		eap_type_header->get_header_buffer(eap_type_header->get_header_buffer_length()),
		eap_type_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(eap_type_header->get_type())
		!= eap_tlv_message_type_eap_type)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_status_e status = eap_expanded_type_c::read_type(
		m_am_tools,
		0ul,
		eap_type_header->get_value(eap_type_header->get_value_length()),
		eap_type_header->get_value_length(),
		eap_type);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const settings_header,
	eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		settings_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_method_settings_c *)"),
		settings_header->get_header_buffer(settings_header->get_header_buffer_length()),
		settings_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(settings_header->get_type())
		!= eap_tlv_message_type_eap_method_settings)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c settings_data(m_am_tools);

	if (settings_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = settings_data.set_message_data(
		settings_header->get_value_length(),
		settings_header->get_value(settings_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> settings_members(m_am_tools);

	status = settings_data.parse_message_data(&settings_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_completion_status\n"),
		settings_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

	status = read_parameter_data(
		&settings_members,
		member_index,
		eap_tlv_message_type_eap_status,
		&(internal_settings->m_completion_status));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	++member_index;

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_EAPType\n"),
		settings_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

	status = read_parameter_data(
		&settings_members,
		member_index,
		&(internal_settings->m_EAPType));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	++member_index;

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_IndexType\n"),
		settings_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

	status = read_parameter_data(
		&settings_members,
		member_index,
		&(internal_settings->m_IndexType));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	++member_index;

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_Index\n"),
		settings_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

	status = read_parameter_data(
		&settings_members,
		member_index,
		&(internal_settings->m_Index));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseAutomaticCACertificatePresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Use automatic CA certificate.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_UseAutomaticCACertificatePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseAutomaticCACertificatePresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseAutomaticCACertificate\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_UseAutomaticCACertificate));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseAutomaticUsernamePresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Use automatic username.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_UseAutomaticUsernamePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseAutomaticUsernamePresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseAutomaticUsername\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_UseAutomaticUsername));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseAutomaticRealmPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Use automatic username.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_UseAutomaticRealmPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseAutomaticRealmPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseAutomaticRealm\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_UseAutomaticRealm));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UsernamePresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Username in ASCII format
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_UsernamePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UsernamePresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_Username_fix\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_Username_fix));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PasswordExistPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Password existence
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_PasswordExistPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PasswordExistPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PasswordExist\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_PasswordExist));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PasswordPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Password in ASCII format
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_PasswordPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PasswordPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_Password\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_Password));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_RealmPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Realm in ASCII format
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_RealmPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_RealmPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_Realm\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_Realm));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UsePseudonymsPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Use pseudonym identities in EAP-SIM/AKA
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_UsePseudonymsPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UsePseudonymsPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UsePseudonyms\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_UsePseudonyms));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_VerifyServerRealmPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Whether EAP-TLS/TTLS/PEAP should verify server realm
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_VerifyServerRealmPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_VerifyServerRealmPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_VerifyServerRealm\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_VerifyServerRealm));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_RequireClientAuthenticationPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Whether EAP-TLS/TTLS/PEAP should require client authentication
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_RequireClientAuthenticationPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_RequireClientAuthenticationPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_RequireClientAuthentication\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_RequireClientAuthentication));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_SessionValidityTimePresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// General session validity time (in minutes)
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_SessionValidityTimePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_SessionValidityTimePresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_SessionValidityTime\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_SessionValidityTime));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_CipherSuitesPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// An array of allowed cipher suites for EAP-TLS/TTLS/PEAP.
		// Refer to RFC2246 chapter A.5 for the values.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_CipherSuitesPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_CipherSuitesPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_CipherSuites\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_CipherSuites));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PEAPVersionsPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Which EAP-PEAP versions are allowed
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_PEAPVersionsPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PEAPVersionsPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PEAPv0Allowed\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_PEAPv0Allowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PEAPv1Allowed\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_PEAPv1Allowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PEAPv2Allowed\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_PEAPv2Allowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_CertificatesPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

  		// Array listing the allowed certificates for EAP-TLS/TTLS/PEAP.
  		// Subject key ID and Certificate type are the only mandatory certificate
  		// details needed at the moment.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_CertificatesPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_CertificatesPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_Certificates\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_Certificates));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_EnabledEncapsulatedEAPTypesPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Array listing the encapsulated EAP types (in priority order).
		// Use EAP type values from eap_type_value_e.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_EnabledEncapsulatedEAPTypesPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_EnabledEncapsulatedEAPTypesPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_EnabledEncapsulatedEAPTypes\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_EnabledEncapsulatedEAPTypes));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_DisabledEncapsulatedEAPTypesPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Array listing the encapsulated EAP types (in priority order).
		// Use EAP type values from eap_type_value_e.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_DisabledEncapsulatedEAPTypesPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_DisabledEncapsulatedEAPTypesPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_DisabledEncapsulatedEAPTypes\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_DisabledEncapsulatedEAPTypes));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_AuthProvModeAllowedPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Whether Authenticated provisioning mode allowed or not in EAP-FAST.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_AuthProvModeAllowedPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_AuthProvModeAllowedPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_AuthProvModeAllowed\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_AuthProvModeAllowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UnauthProvModeAllowedPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Whether Unauthenticated provisioning mode allowed or not in EAP-FAST.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_UnauthProvModeAllowedPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UnauthProvModeAllowedPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UnauthProvModeAllowed\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_UnauthProvModeAllowed));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PACGroupReferencePresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// PAC group reference in ASCII format for EAP-FAST.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_PACGroupReferencePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_PACGroupReferencePresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_PACGroupReference\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_PACGroupReference));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_WarnADHPNoPACPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Whether to Warn (or Prompt) for ADHP (Authenticated Diffie-Hellman Protocol)
		// auto-provisioning when there is no PAC at all. EAP-FAST specific.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_WarnADHPNoPACPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_WarnADHPNoPACPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_WarnADHPNoPAC\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_WarnADHPNoPAC));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_WarnADHPNoMatchingPACPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Whether to Warn (or Prompt) for ADHP auto-provisioning when
		// there is no PAC that matches the A-ID sent by server. EAP-FAST specific.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_WarnADHPNoMatchingPACPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_WarnADHPNoMatchingPACPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_WarnADHPNoMatchingPAC\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_WarnADHPNoMatchingPAC));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_WarnNotDefaultServerPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Whether to Warn (or Prompt) when client encouters a server that has provisioned
		// the client with a PAC before but is not currently selected as the default server.
		// EAP-FAST specific.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_WarnNotDefaultServerPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_WarnNotDefaultServerPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_WarnNotDefaultServer\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_WarnNotDefaultServer));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_SelectedEAPTypesPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		// Array listing the active and disabled EAP types (in priority order).
		// Use EAP type values from eap_type_value_e.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_SelectedEAPTypesPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_SelectedEAPTypesPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_active_eap_methods\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_active_eap_methods));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_disabled_eap_methods\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_disabled_eap_methods));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_TunnelingTypePresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_TunnelingTypePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_TunnelingTypePresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_TunnelingType\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_TunnelingType));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_DestinationIndexAndTypePresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_DestinationIndexAndTypePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_DestinationIndexAndTypePresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_DestinationIndexType\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_DestinationIndexType));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_DestinationIndex\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_DestinationIndex));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_MethodInfoPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_MethodInfoPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_MethodInfoPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_KReleaseDate\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_KReleaseDate));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_KEapTypeVersion\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_KEapTypeVersion));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_KManufacturer\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_KManufacturer));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_ButtonIdPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_ButtonIdPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_ButtonIdPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_ButtonId\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_ButtonId));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_ShowPassWordPromptPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_ShowPassWordPromptPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_ShowPassWordPromptPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_ShowPassWordPrompt\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_ShowPassWordPrompt));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			EAP_TRACE_FLAGS_MESSAGE_DATA,
			(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseIdentityPrivacyPresent\n"),
			settings_header->get_type(),
			 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

		status = read_parameter_data(
			&settings_members,
			member_index,
			&(internal_settings->m_UseIdentityPrivacyPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (internal_settings->m_UseIdentityPrivacyPresent == true)
		{
			++member_index;

			EAP_TRACE_DEBUG(
				m_am_tools,
				EAP_TRACE_FLAGS_MESSAGE_DATA,
				(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s, m_UseIdentityPrivacy\n"),
				settings_header->get_type(),
				 get_type_string(static_cast<eap_tlv_message_type_e>(settings_header->get_type()))));

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(internal_settings->m_UseIdentityPrivacy));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const cert_entry_header,
	eap_certificate_entry_c * const cert_entry)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		cert_entry_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(cert_entry_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_certificate_entry_c *)"),
		cert_entry_header->get_header_buffer(cert_entry_header->get_header_buffer_length()),
		cert_entry_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(cert_entry_header->get_type())
		!= eap_tlv_message_type_eap_certificate_entry)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c settings_data(m_am_tools);

	if (settings_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = settings_data.set_message_data(
		cert_entry_header->get_value_length(),
		cert_entry_header->get_value(cert_entry_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> settings_members(m_am_tools);

	status = settings_data.parse_message_data(&settings_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		// Specifies whether this entry describes user or CA certificate (mandatory)
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_CertType));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	{
		// Subject name in distinguished name ASCII form. This is optional.
		// For example "/C=US/O=Some organization/CN=Some common name".
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_SubjectNamePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_SubjectNamePresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_SubjectName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// Issuer name in distinguished name ASCII form. This is optional.
		// For example "/C=US/O=Some organization/CN=Some common name".
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_IssuerNamePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_IssuerNamePresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_IssuerName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// Serial number in ASCII form. This is optional.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_SerialNumberPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_SerialNumberPresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_SerialNumber));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// Subject key in binary form. This is mandatory.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_SubjectKeyIDPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_SubjectKeyIDPresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_SubjectKeyID));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// Subject key in binary form. This is mandatory.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_ThumbprintPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_ThumbprintPresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_Thumbprint));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// This holds only the certificate label. This is the text UI will show.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_LabelPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_LabelPresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_Label));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// Primary name of the certificate if any, UI uses this.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_PrimaryNamePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_PrimaryNamePresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_PrimaryName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// Secondary name of the certificate if any, UI uses this.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_SecondaryNamePresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_SecondaryNamePresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_SecondaryName));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	++member_index;

	{
		// UI uses this to indicate enabled certificate.
		status = read_parameter_data(
			&settings_members,
			member_index,
			&(cert_entry->m_iIsEnabledPresent));
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (cert_entry->m_iIsEnabledPresent == true)
		{
			++member_index;

			status = read_parameter_data(
				&settings_members,
				member_index,
				&(cert_entry->m_iIsEnabled));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const ushort_array_header,
	eap_array_c<u16_t> * const ushort_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		ushort_array_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(ushort_array_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_array_c<u16_t> *)"),
		ushort_array_header->get_header_buffer(ushort_array_header->get_header_buffer_length()),
		ushort_array_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(ushort_array_header->get_type())
		!= eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c ushort_array_data(m_am_tools);

	if (ushort_array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = ushort_array_data.set_message_data(
		ushort_array_header->get_value_length(),
		ushort_array_header->get_value(ushort_array_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> ushort_array_members(m_am_tools);

	status = ushort_array_data.parse_message_data(&ushort_array_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_member = 0ul; ind_member < ushort_array_members.get_object_count(); ind_member++)
	{
		u16_t * const ushort_value = new u16_t;

		eap_automatic_variable_c<u16_t> automatic_ushort_value(m_am_tools, ushort_value);

		if (ushort_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			const eap_tlv_header_c * const ushort_header = ushort_array_members.get_object(ind_member);
			if (ushort_header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = ushort_array_data.get_parameter_data(ushort_header, ushort_value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_ushort_value.do_not_free_variable();

			status = ushort_array->add_object(ushort_value, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_process_tlv_message_data_c::get_payload_size(
	EAP_TEMPLATE_CONST eap_array_c<eap_type_value_e> * const eap_type_array) const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_payload_size(eap_array_c<eap_type_value_e> * )\n")));

	u32_t size = eap_type_array->get_object_count()
				* (eap_tlv_header_c::get_header_length()
					+ eap_expanded_type_c::get_eap_expanded_type_size()); // Size of eap_type_value_e

	return (size);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::add_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_type_value_e> * const eap_type_array)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::add_parameter_data(eap_array_c<eap_type_value_e> * )\n")));

	const u32_t size_of_eap_type_array(get_payload_size(eap_type_array));

	eap_status_e status = add_structured_parameter_header(
		eap_tlv_message_type_array,
		size_of_eap_type_array);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t ind = 0ul; ind < eap_type_array->get_object_count(); ind++)
	{
		const eap_type_value_e * const value = eap_type_array->get_object(ind);
		if (value != 0)
		{
			status = add_parameter_data(*value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const eap_type_array_header,
	eap_array_c<eap_type_value_e> * const eap_type_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		eap_type_array_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(eap_type_array_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_array_c<eap_type_value_e> *)"),
		eap_type_array_header->get_header_buffer(eap_type_array_header->get_header_buffer_length()),
		eap_type_array_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(eap_type_array_header->get_type())
		!= eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c ushort_array_data(m_am_tools);

	if (ushort_array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = ushort_array_data.set_message_data(
		eap_type_array_header->get_value_length(),
		eap_type_array_header->get_value(eap_type_array_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> ushort_array_members(m_am_tools);

	status = ushort_array_data.parse_message_data(&ushort_array_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_member = 0ul; ind_member < ushort_array_members.get_object_count(); ind_member++)
	{
		eap_type_value_e * const eap_type_value = new eap_type_value_e();

		eap_automatic_variable_c<eap_type_value_e> automatic_eap_type_value(m_am_tools, eap_type_value);

		if (eap_type_value == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			const eap_tlv_header_c * const eap_type_value_header = ushort_array_members.get_object(ind_member);
			if (eap_type_value_header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = ushort_array_data.get_parameter_data(eap_type_value_header, eap_type_value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_eap_type_value.do_not_free_variable();

			status = eap_type_array->add_object(eap_type_value, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const cert_array_header,
	eap_array_c<eap_certificate_entry_c> * const cert_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		cert_array_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(cert_array_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_array_c<eap_certificate_entry_c> *)"),
		cert_array_header->get_header_buffer(cert_array_header->get_header_buffer_length()),
		cert_array_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(cert_array_header->get_type())
		!= eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c cert_array_data(m_am_tools);

	if (cert_array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = cert_array_data.set_message_data(
		cert_array_header->get_value_length(),
		cert_array_header->get_value(cert_array_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> cert_array_members(m_am_tools);

	status = cert_array_data.parse_message_data(&cert_array_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_member = 0ul; ind_member < cert_array_members.get_object_count(); ind_member++)
	{
		eap_certificate_entry_c * const cert_entry = new eap_certificate_entry_c(m_am_tools);

		eap_automatic_variable_c<eap_certificate_entry_c> automatic_cert_entry(m_am_tools, cert_entry);

		if (cert_entry == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			const eap_tlv_header_c * const cert_entry_header = cert_array_members.get_object(ind_member);
			if (cert_entry_header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = cert_array_data.get_parameter_data(cert_entry_header, cert_entry);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_cert_entry.do_not_free_variable();

			status = cert_array->add_object(cert_entry, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const network_key_header,
	network_key_and_index_c * const network_key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		network_key_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(network_key_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(network_key_and_index_c *)"),
		network_key_header->get_header_buffer(network_key_header->get_header_buffer_length()),
		network_key_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(network_key_header->get_type())
		!= eap_tlv_message_type_network_key)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c credential_data(m_am_tools);

	if (credential_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_data.set_message_data(
		network_key_header->get_value_length(),
		network_key_header->get_value(network_key_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_members(m_am_tools);

	status = credential_data.parse_message_data(&credential_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	u8_t network_key_index(0ul);

	{
		const eap_tlv_header_c * const network_key_index_header = credential_members.get_object(member_index);
		if (network_key_index_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(network_key_index_header, &network_key_index);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	eap_variable_data_c key(m_am_tools);

	{
		const eap_tlv_header_c * const key_header = credential_members.get_object(member_index);
		if (key_header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		status = credential_data.get_parameter_data(key_header, &key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	++member_index;

	network_key->set_network_key_index(network_key_index);

	status = network_key->get_network_key()->set_copy_of_buffer(&key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const network_keys_array_header,
	eap_array_c<network_key_and_index_c> * const network_keys_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		network_keys_array_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(network_keys_array_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_array_c<network_key_and_index_c> *)"),
		network_keys_array_header->get_header_buffer(network_keys_array_header->get_header_buffer_length()),
		network_keys_array_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(network_keys_array_header->get_type())
		!= eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c credential_array_data(m_am_tools);

	if (credential_array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_array_data.set_message_data(
		network_keys_array_header->get_value_length(),
		network_keys_array_header->get_value(network_keys_array_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_array_members(m_am_tools);

	status = credential_array_data.parse_message_data(&credential_array_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_member = 0ul; ind_member < credential_array_members.get_object_count(); ind_member++)
	{
		network_key_and_index_c * const network_key = new network_key_and_index_c(m_am_tools);

		eap_automatic_variable_c<network_key_and_index_c> automatic_network_key(m_am_tools, network_key);

		if (network_key == 0
			|| network_key->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			const eap_tlv_header_c * const simple_config_credential_header = credential_array_members.get_object(ind_member);
			if (simple_config_credential_header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = credential_array_data.get_parameter_data(simple_config_credential_header, network_key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_network_key.do_not_free_variable();

			status = network_keys_array->add_object(network_key, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const credential_header,
	simple_config_credential_c * const credential)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		credential_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(credential_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(simple_config_credential_c *)"),
		credential_header->get_header_buffer(credential_header->get_header_buffer_length()),
		credential_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(credential_header->get_type())
		!= eap_tlv_message_type_protected_setup_credential)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c credential_data(m_am_tools);

	if (credential_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_data.set_message_data(
		credential_header->get_value_length(),
		credential_header->get_value(credential_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_members(m_am_tools);

	status = credential_data.parse_message_data(&credential_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	u32_t member_index(0ul);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	u8_t network_index(0ul);

	status = credential_data.read_parameter_data(
			&credential_members,
			member_index,
			&network_index);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++member_index;

	eap_variable_data_c SSID(m_am_tools);

	status = credential_data.read_parameter_data(
			&credential_members,
			member_index,
			&SSID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++member_index;

	simple_config_Authentication_Type_e authentication_type(simple_config_Authentication_Type_None);

	status = credential_data.read_parameter_data(
			&credential_members,
			member_index,
			&authentication_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++member_index;

	simple_config_Encryption_Type_e encryption_type(simple_config_Encryption_Type_None);

	status = credential_data.read_parameter_data(
			&credential_members,
			member_index,
			&encryption_type);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++member_index;

	 eap_array_c<network_key_and_index_c> network_keys_array(m_am_tools);

	status = credential_data.read_parameter_data(
			&credential_members,
			member_index,
			&network_keys_array);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	++member_index;

	 eap_variable_data_c MAC_address(m_am_tools);

	status = credential_data.read_parameter_data(
			&credential_members,
			member_index,
			&MAC_address);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	credential->set_network_index(network_index);

	status = credential->get_SSID()->set_copy_of_buffer(&SSID);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	credential->set_Authentication_Type(authentication_type);

	credential->set_Encryption_Type(encryption_type);

	status = copy(
		&network_keys_array,
		credential->get_network_keys(),
		m_am_tools,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = credential->get_MAC_address()->set_copy_of_buffer(&MAC_address);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::get_parameter_data(
	const eap_tlv_header_c * const credential_array_header,
	eap_array_c<simple_config_credential_c> * const credential_array)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("eap_process_tlv_message_data_c::get_parameter_data(): type=%d=%s\n"),
		credential_array_header->get_type(),
		 get_type_string(static_cast<eap_tlv_message_type_e>(credential_array_header->get_type()))));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		EAP_TRACE_FLAGS_MESSAGE_DATA,
		(EAPL("get_parameter_data(eap_array_c<simple_config_credential_c> *)"),
		credential_array_header->get_header_buffer(credential_array_header->get_header_buffer_length()),
		credential_array_header->get_header_buffer_length()));

	if (static_cast<eap_tlv_message_type_e>(credential_array_header->get_type())
		!= eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_payload);
	}

	eap_process_tlv_message_data_c credential_array_data(m_am_tools);

	if (credential_array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = credential_array_data.set_message_data(
		credential_array_header->get_value_length(),
		credential_array_header->get_value(credential_array_header->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> credential_array_members(m_am_tools);

	status = credential_array_data.parse_message_data(&credential_array_members);

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (u32_t ind_member = 0ul; ind_member < credential_array_members.get_object_count(); ind_member++)
	{
		simple_config_credential_c * const simple_config_credential = new simple_config_credential_c(m_am_tools);

		eap_automatic_variable_c<simple_config_credential_c> automatic_simple_config_credential(m_am_tools, simple_config_credential);

		if (simple_config_credential == 0
			|| simple_config_credential->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		{
			const eap_tlv_header_c * const simple_config_credential_header = credential_array_members.get_object(ind_member);
			if (simple_config_credential_header == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			status = credential_array_data.get_parameter_data(simple_config_credential_header, simple_config_credential);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			automatic_simple_config_credential.do_not_free_variable();

			status = credential_array->add_object(simple_config_credential, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // for ()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_am_network_id_c * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_network_id)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_variable_data_c * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_variable_data)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	const eap_tlv_message_type_e type,
	eap_status_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != static_cast<eap_tlv_type_t>(type))
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t value(0ul);

	eap_status_e status = get_parameter_data(positional_parameter, &value);

	*out_data = static_cast<eap_status_e>(value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_array_c<eap_am_network_id_c> * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const array_of_network_ids
		= parameters->get_object(parameter_index);

	if (array_of_network_ids == 0
		|| array_of_network_ids->get_type() != eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_process_tlv_message_data_c array_data(m_am_tools);

	if (array_data.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = array_data.set_message_data(
		array_of_network_ids->get_value_length(),
		array_of_network_ids->get_value(array_of_network_ids->get_value_length()));

	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> network_ids(m_am_tools);

	status = array_data.parse_message_data(
		&network_ids);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t ind = 0ul; ind < network_ids.get_object_count(); ++ind)
	{
		const eap_tlv_header_c * const header = network_ids.get_object(ind);

		if (header == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
		}

		eap_am_network_id_c * const new_network_id = new eap_am_network_id_c(m_am_tools);
		if (new_network_id == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_automatic_variable_c<eap_am_network_id_c> automatic_new_network_id(m_am_tools, new_network_id);

		status = array_data.get_parameter_data(header, new_network_id);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		automatic_new_network_id.do_not_free_variable();

		status = out_data->add_object(
			new_network_id,
			true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	} // for()

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_state_notification_c * * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_eap_state_notification)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eapol_RSNA_key_header_c::eapol_RSNA_cipher_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_RSNA_cipher)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t value(0ul);

	eap_status_e status = get_parameter_data(positional_parameter, &value);

	*out_data = static_cast<eapol_RSNA_key_header_c::eapol_RSNA_cipher_e>(value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	bool * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_boolean)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t value(0ul);

	eap_status_e status = get_parameter_data(positional_parameter, &value);

	*out_data = (value == 0) ? false: true;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_type_value_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_eap_type)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eapol_key_authentication_type_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_eapol_key_authentication_type)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t value(0ul);

	eap_status_e status = get_parameter_data(positional_parameter, &value);

	*out_data = static_cast<eapol_key_authentication_type_e>(value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eapol_session_key_c * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_session_key)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_tlv_message_type_function_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_function)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eapol_key_802_11_authentication_mode_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_eapol_key_802_11_authentication_mode)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t value(0ul);

	eap_status_e status = get_parameter_data(positional_parameter, &value);

	*out_data = static_cast<eapol_key_802_11_authentication_mode_e>(value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_eapol_tkip_mic_failure_type)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t value(0ul);

	eap_status_e status = get_parameter_data(positional_parameter, &value);

	*out_data = static_cast<eapol_RSNA_key_header_c::eapol_tkip_mic_failure_type_e>(value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eapol_wlan_authentication_state_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_eapol_wlan_authentication_state)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t value(0ul);

	eap_status_e status = get_parameter_data(positional_parameter, &value);

	*out_data = static_cast<eapol_wlan_authentication_state_e>(value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	u64_t * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_u64_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	u32_t * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_u32_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	u16_t * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_u16_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	u8_t * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_u8_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	i32_t * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_i32_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	i16_t * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_i16_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	i8_t * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_i8_t)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_method_settings_c * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_eap_method_settings)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	out_data->trace();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_array_c<u16_t> * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_array_c<eap_type_value_e> * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_array_c<eap_certificate_entry_c> * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_certificate_entry_c::eap_certificate_type_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t integer_value(0ul);

	eap_status_e status = read_parameter_data(
		parameters,
		parameter_index,
		&integer_value);

	*out_data = static_cast<eap_certificate_entry_c::eap_certificate_type_e>(integer_value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	simple_config_Encryption_Type_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u16_t integer_value(0ul);

	eap_status_e status = read_parameter_data(
		parameters,
		parameter_index,
		&integer_value);

	*out_data = static_cast<simple_config_Encryption_Type_e>(integer_value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	simple_config_Authentication_Type_e * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u16_t integer_value(0ul);

	eap_status_e status = read_parameter_data(
		parameters,
		parameter_index,
		&integer_value);

	*out_data = static_cast<simple_config_Authentication_Type_e>(integer_value);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_array_c<simple_config_credential_c> * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

#if defined(USE_EAP_SIMPLE_CONFIG)

EAP_FUNC_EXPORT eap_status_e eap_process_tlv_message_data_c::read_parameter_data(
	EAP_TEMPLATE_CONST eap_array_c<eap_tlv_header_c> * const parameters,
	const u32_t parameter_index,
	eap_array_c<network_key_and_index_c> * const out_data)
{
	if (parameters == 0
		|| out_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const eap_tlv_header_c * const positional_parameter
		= parameters->get_object(parameter_index);

	if (positional_parameter == 0
		|| positional_parameter->get_type() != eap_tlv_message_type_array)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = get_parameter_data(positional_parameter, out_data);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

#endif // #if defined(USE_EAP_SIMPLE_CONFIG)

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_process_tlv_message_data_c::get_type_string(const eap_tlv_message_type_e type)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(type, eap_tlv_message_type_none)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_array)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_boolean)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eap_protocol_layer)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eap_state_notification)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eap_status)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eap_type)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eapol_key_802_11_authentication_mode)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eapol_key_authentication_type)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eapol_key_type)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eapol_tkip_mic_failure_type)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eapol_wlan_authentication_state)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_error)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_function)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_network_id)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_network_key)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_protected_setup_credential)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_RSNA_cipher)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_session_key)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_u8_t)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_u16_t)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_u32_t)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_u64_t)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_variable_data)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eap_method_settings)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_eap_certificate_entry)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_i8_t)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_i16_t)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_i32_t)
	else EAP_IF_RETURN_STRING(type, eap_tlv_message_type_configuration_option)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(type);

		return EAPL("Unknown EAPOL-TLV message type");
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_const_string eap_process_tlv_message_data_c::get_function_string(const eap_tlv_message_type_function_e function)
{
#if defined(USE_EAP_TRACE_STRINGS)
	EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_none)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_check_pmksa_cache)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_start_authentication)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_association)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_disassociation)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_start_preauthentication)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_start_reassociation)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_reassociation)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_start_WPXM_reassociation)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_WPXM_reassociation)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_packet_process)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_tkip_mic_failure)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_eap_acknowledge)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_update_header_offset)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_check_pmksa_cache)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_packet_send)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_associate)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_disassociate)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_packet_data_session_key)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_state_notification)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_reassociate)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_update_wlan_database_reference_values)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_start_WPXM_reassociation)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_new_protected_setup_credentials)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_create_eap_session)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_remove_eap_session)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_send_eap_identity_request)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_packet_data_crypto_keys)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_restart_authentication)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_create_state)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_remove_bksa_from_cache)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_association)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_set_eap_database_reference_values)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_eap_mtu)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_get_802_11_authentication_mode)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_get_802_11_authentication_mode)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_remove_eap_session)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_complete_disassociation)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_last_function)

	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_get_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_set_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_copy_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_delete_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_set_index)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_get_type_info)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_invoke_ui)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_complete_get_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_complete_set_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_complete_delete_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_complete_copy_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_complete_set_index)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_complete_get_type_info)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_complete_invoke_ui)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_plugin_last_function)

	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_set_eap_methods)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_get_eap_methods)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_get_certificate_lists)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_delete_all_eap_settings)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_copy_all_eap_settings)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_complete_set_eap_methods)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_complete_get_eap_methods)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_complete_get_certificate_lists)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_complete_delete_all_eap_settings)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_complete_copy_all_eap_settings)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_general_settings_last_function)

	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_open_pac_store)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_create_device_seed)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_is_master_key_present)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_is_master_key_and_password_matching)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_create_and_save_master_key)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_compare_pac_store_password)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_is_pacstore_password_present)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_set_pac_store_password)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_destroy_pac_store)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_open_pac_store)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_create_device_seed)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_is_master_key_present)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_is_master_key_and_password_matching)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_create_and_save_master_key)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_is_pacstore_password_present)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_compare_pac_store_password)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_set_pac_store_password)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_complete_destroy_pac_store)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_pac_store_last_function)

	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_get_all_certificate_labels)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_reset_certificate_store)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_get_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_set_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_set_ca_cert)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_set_user_cert)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_delete_configuration)

	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_get_all_certificate_labels)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_reset_certificate_store)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_get_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_set_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_set_ca_cert)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_set_user_cert)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_delete_configuration)
	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_wapi_settings_complete_last_function)

	else EAP_IF_RETURN_STRING(function, eap_tlv_message_type_function_illegal_value)
	else
#endif // #if defined(USE_EAP_TRACE_STRINGS)
	{
		EAP_UNREFERENCED_PARAMETER(function);

		return EAPL("Unknown EAPOL-TLV message function");
	}
}

//--------------------------------------------------

// End.
