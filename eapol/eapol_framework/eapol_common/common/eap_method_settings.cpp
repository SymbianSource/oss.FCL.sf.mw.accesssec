/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-settings class.
*
*/

/*
* %version: 24 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 759 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "eap_method_settings.h"
#include "eap_array_algorithms.h"
#include "eap_automatic_variable.h"

//-------------------------------------------------------------------------------

eap_certificate_entry_c::~eap_certificate_entry_c()
{
}

//-------------------------------------------------------------------------------

eap_certificate_entry_c::eap_certificate_entry_c(
	abs_eap_am_tools_c * const tools)
: m_am_tools(tools)
, m_CertType(eap_certificate_type_none)
, m_SubjectNamePresent(false)
, m_SubjectName(tools)
, m_IssuerNamePresent(false)
, m_IssuerName(tools)
, m_SerialNumberPresent(false)
, m_SerialNumber(tools)
, m_SubjectKeyIDPresent(false)
, m_SubjectKeyID(tools)
, m_ThumbprintPresent(false)
, m_Thumbprint(tools)
, m_LabelPresent(false)
, m_Label(tools)
, m_PrimaryNamePresent(false)
, m_PrimaryName(tools)
, m_SecondaryNamePresent(false)
, m_SecondaryName(tools)
, m_iIsEnabledPresent(false)
, m_iIsEnabled(false)
{
}

//-------------------------------------------------------------------------------

bool eap_certificate_entry_c::get_is_valid()
{
	return true;
}

//-------------------------------------------------------------------------------

bool eap_certificate_entry_c::get_is_valid_data()
{
	return get_is_valid();
}

//-------------------------------------------------------------------------------

eap_certificate_entry_c * eap_certificate_entry_c::copy()
{
	eap_certificate_entry_c * const new_entry = new eap_certificate_entry_c(m_am_tools);

	eap_automatic_variable_c<eap_certificate_entry_c> automatic_new_entry(
		m_am_tools,
		new_entry);

	if (new_entry == 0
		|| new_entry->get_is_valid() == false)
	{
		(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		return 0;
	}

	eap_status_e status(eap_status_ok);

	new_entry->m_CertType = m_CertType;

	new_entry->m_SubjectNamePresent = m_SubjectNamePresent;
	if (m_SubjectNamePresent == true)
	{
		status = new_entry->m_SubjectName.set_copy_of_buffer(&m_SubjectName);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_IssuerNamePresent = m_IssuerNamePresent;
	if (m_IssuerNamePresent == true)
	{
		status = new_entry->m_IssuerName.set_copy_of_buffer(&m_IssuerName);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_SerialNumberPresent = m_SerialNumberPresent;
	if (m_SerialNumberPresent == true)
	{
		status = new_entry->m_SerialNumber.set_copy_of_buffer(&m_SerialNumber);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_SubjectKeyIDPresent = m_SubjectKeyIDPresent;
	if (m_SubjectKeyIDPresent == true)
	{
		status = new_entry->m_SubjectKeyID.set_copy_of_buffer(&m_SubjectKeyID);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_ThumbprintPresent = m_ThumbprintPresent;
	if (m_ThumbprintPresent == true)
	{
		status = new_entry->m_Thumbprint.set_copy_of_buffer(&m_Thumbprint);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_LabelPresent = m_LabelPresent;
	if (m_LabelPresent == true)
	{
		status = new_entry->m_Label.set_copy_of_buffer(&m_Label);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_PrimaryNamePresent = m_PrimaryNamePresent;
	if (m_PrimaryNamePresent == true)
	{
		status = new_entry->m_PrimaryName.set_copy_of_buffer(&m_PrimaryName);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_SecondaryNamePresent = m_SecondaryNamePresent;
	if (m_SecondaryNamePresent == true)
	{
		status = new_entry->m_SecondaryName.set_copy_of_buffer(&m_SecondaryName);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}
	}

	new_entry->m_iIsEnabledPresent = m_iIsEnabledPresent;
	new_entry->m_iIsEnabled = m_iIsEnabled;

	automatic_new_entry.do_not_free_variable();

	return new_entry;
}

//-------------------------------------------------------------------------------

void eap_certificate_entry_c::trace() const
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_CertType=%d\n"),
		m_CertType));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_SubjectNamePresent=%d\n"),
		m_SubjectNamePresent));
	if (m_SubjectNamePresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_SubjectName"),
			m_SubjectName.get_data(),
			m_SubjectName.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_IssuerNamePresent=%d\n"),
		m_IssuerNamePresent));
	if (m_IssuerNamePresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_IssuerName"),
			m_IssuerName.get_data(),
			m_IssuerName.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_SerialNumberPresent=%d\n"),
		m_SerialNumberPresent));
	if (m_SerialNumberPresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_SerialNumber"),
			m_SerialNumber.get_data(),
			m_SerialNumber.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_SubjectKeyIDPresent=%d\n"),
		m_SubjectKeyIDPresent));
	if (m_SubjectKeyIDPresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_SubjectKeyID"),
			m_SubjectKeyID.get_data(),
			m_SubjectKeyID.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_ThumbprintPresent=%d\n"),
		m_ThumbprintPresent));
	if (m_ThumbprintPresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_Thumbprint"),
			m_Thumbprint.get_data(),
			m_Thumbprint.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_LabelPresent=%d\n"),
		m_LabelPresent));
	if (m_LabelPresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_Label"),
			m_Label.get_data(),
			m_Label.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_PrimaryNamePresent=%d\n"),
		m_PrimaryNamePresent));
	if (m_PrimaryNamePresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_PrimaryName"),
			m_PrimaryName.get_data(),
			m_PrimaryName.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_SecondaryNamePresent=%d\n"),
		m_SecondaryNamePresent));
	if (m_SecondaryNamePresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_certificate_entry_c::trace():     m_SecondaryName"),
			m_SecondaryName.get_data(),
			m_SecondaryName.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_certificate_entry_c::trace(): m_iIsEnabledPresent=%d\n"),
		m_iIsEnabledPresent));
	if (m_iIsEnabledPresent == true)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_certificate_entry_c::trace():     m_iIsEnabled=%d\n"),
			m_iIsEnabled));
	}
}

//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------

eap_method_values_c::~eap_method_values_c()
{
}

//-------------------------------------------------------------------------------

eap_method_values_c::eap_method_values_c(
	abs_eap_am_tools_c * const tools)
: m_am_tools(tools)
, m_is_valid(false)
, m_completion_status(eap_status_process_general_error)
, m_EAPType(eap_type_none)
, m_IndexType(0ul)
, m_Index(0ul)
, m_UseAutomaticCACertificatePresent(false)
, m_UseAutomaticCACertificate(false)
, m_UseAutomaticUsernamePresent(false)
, m_UseAutomaticUsername(false)
, m_UseAutomaticRealmPresent(false)
, m_UseAutomaticRealm(false)
, m_UsernamePresent(false)
, m_Username_fix(tools)
, m_PasswordExistPresent(false)
, m_PasswordPresent(false)
, m_Password(tools)
, m_RealmPresent(false)
, m_Realm(tools)
, m_UsePseudonymsPresent(false)
, m_UsePseudonyms(false)
, m_VerifyServerRealmPresent(false)
, m_VerifyServerRealm(false)
, m_RequireClientAuthenticationPresent(false)
, m_RequireClientAuthentication(false)
, m_SessionValidityTimePresent(false)
, m_SessionValidityTime(0ul)
, m_CipherSuitesPresent(false)
, m_CipherSuites(tools)
, m_PEAPVersionsPresent(false)
, m_PEAPv0Allowed(false)
, m_PEAPv1Allowed(false)
, m_PEAPv2Allowed(false)
, m_CertificatesPresent(false)
, m_Certificates(tools)
, m_EnabledEncapsulatedEAPTypesPresent(false)
, m_EnabledEncapsulatedEAPTypes(tools)
, m_DisabledEncapsulatedEAPTypesPresent(false)
, m_DisabledEncapsulatedEAPTypes(tools)
, m_AuthProvModeAllowedPresent(false)
, m_AuthProvModeAllowed(false)
, m_UnauthProvModeAllowedPresent(false)
, m_UnauthProvModeAllowed(false)
, m_PACGroupReferencePresent(false)
, m_PACGroupReference(tools)
, m_WarnADHPNoPACPresent(false)
, m_WarnADHPNoPAC(false)
, m_WarnADHPNoMatchingPACPresent(false)
, m_WarnADHPNoMatchingPAC(false)
, m_WarnNotDefaultServerPresent(false)
, m_WarnNotDefaultServer(false)
, m_SelectedEAPTypesPresent(false)
, m_active_eap_methods(tools)
, m_disabled_eap_methods(tools)
, m_TunnelingTypePresent(false)
, m_TunnelingType(eap_type_none)
, m_DestinationIndexAndTypePresent(false)
, m_DestinationIndexType(0ul)
, m_DestinationIndex(0ul)
, m_MethodInfoPresent(false)
, m_KReleaseDate(tools)
, m_KEapTypeVersion(tools)
, m_KManufacturer(tools)
, m_ButtonIdPresent(false)
, m_ButtonId(0)
, m_ShowPassWordPromptPresent(false)
, m_ShowPassWordPrompt(false)
, m_UseIdentityPrivacyPresent(false)
, m_UseIdentityPrivacy(false)
{
}

//-------------------------------------------------------------------------------

abs_eap_am_tools_c * eap_method_values_c::get_am_tools() const
{
	return m_am_tools;
}


//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------
//-------------------------------------------------------------------------------

eap_method_settings_c::~eap_method_settings_c()
{
}

//-------------------------------------------------------------------------------

eap_method_settings_c::eap_method_settings_c(
	abs_eap_am_tools_c * const tools)
	: eap_method_values_c(tools)
{
	m_is_valid = true;
}

//-------------------------------------------------------------------------------

eap_method_settings_c::eap_method_settings_c(
	abs_eap_am_tools_c * const tools,
	const eap_method_settings_c * const init)
	: eap_method_values_c(tools)
{
	eap_status_e status(eap_status_ok);

	// The correct status is set in the end of this function.
	m_completion_status = eap_status_allocation_error;

	m_EAPType = init->m_EAPType;

	m_IndexType = init->m_IndexType;

	m_Index = init->m_Index;

	m_UseAutomaticCACertificatePresent = init->m_UseAutomaticCACertificatePresent;
	m_UseAutomaticCACertificate = init->m_UseAutomaticCACertificate;

	m_UseAutomaticUsernamePresent = init->m_UseAutomaticUsernamePresent;
	m_UseAutomaticUsername = init->m_UseAutomaticUsername;

	m_UseAutomaticRealmPresent = init->m_UseAutomaticRealmPresent;
	m_UseAutomaticRealm = init->m_UseAutomaticRealm;

	m_UsernamePresent = init->m_UsernamePresent;
	if (m_UsernamePresent == true)
	{
		status = m_Username_fix.set_copy_of_buffer(&(init->m_Username_fix));
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_PasswordExistPresent = init->m_PasswordExistPresent;
	m_PasswordExist = init->m_PasswordExist;

	m_PasswordPresent = init->m_PasswordPresent;
	if (m_PasswordPresent == true)
	{
		status = m_Password.set_copy_of_buffer(&(init->m_Password));
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_RealmPresent = init->m_RealmPresent;
	if (m_RealmPresent == true)
	{
		status = m_Realm.set_copy_of_buffer(&(init->m_Realm));
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_UsePseudonymsPresent = init->m_UsePseudonymsPresent;
	m_UsePseudonyms = init->m_UsePseudonyms;

	m_VerifyServerRealmPresent = init->m_VerifyServerRealmPresent;
	m_VerifyServerRealm = init->m_VerifyServerRealm;

	m_RequireClientAuthenticationPresent = init->m_RequireClientAuthenticationPresent;
	m_RequireClientAuthentication = init->m_RequireClientAuthentication;

	m_SessionValidityTimePresent = init->m_SessionValidityTimePresent;
	m_SessionValidityTime = init->m_SessionValidityTime;

	m_CipherSuitesPresent = init->m_CipherSuitesPresent;
	if (m_CipherSuitesPresent == true)
	{
		status = copy_simple<u16_t>(
			&(init->m_CipherSuites),
			&m_CipherSuites,
			tools,
			false);
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_PEAPVersionsPresent = init->m_PEAPVersionsPresent;
	m_PEAPv0Allowed = init->m_PEAPv0Allowed;
	m_PEAPv1Allowed = init->m_PEAPv1Allowed;
	m_PEAPv2Allowed = init->m_PEAPv2Allowed;

	m_CertificatesPresent = init->m_CertificatesPresent;
	if (m_CertificatesPresent == true)
	{
		status = copy<eap_certificate_entry_c>(
			&(init->m_Certificates),
			&m_Certificates,
			tools,
			false);
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_EnabledEncapsulatedEAPTypesPresent = init->m_EnabledEncapsulatedEAPTypesPresent;
	if (m_EnabledEncapsulatedEAPTypesPresent == true)
	{
		status = copy<eap_type_value_e>(
			&(init->m_EnabledEncapsulatedEAPTypes),
			&m_EnabledEncapsulatedEAPTypes,
			tools,
			false);
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_DisabledEncapsulatedEAPTypesPresent = init->m_DisabledEncapsulatedEAPTypesPresent;
	if (m_DisabledEncapsulatedEAPTypesPresent == true)
	{
		status = copy<eap_type_value_e>(
			&(init->m_DisabledEncapsulatedEAPTypes),
			&m_DisabledEncapsulatedEAPTypes,
			tools,
			false);
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_AuthProvModeAllowedPresent = init->m_AuthProvModeAllowedPresent;
	m_AuthProvModeAllowed = init->m_AuthProvModeAllowed;

	m_UnauthProvModeAllowedPresent = init->m_UnauthProvModeAllowedPresent;
	m_UnauthProvModeAllowed = init->m_UnauthProvModeAllowed;

	m_PACGroupReferencePresent = init->m_PACGroupReferencePresent;
	if (m_PACGroupReferencePresent == true)
	{
		status = m_PACGroupReference.set_copy_of_buffer(&(init->m_PACGroupReference));
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_WarnADHPNoPACPresent = init->m_WarnADHPNoPACPresent;
	m_WarnADHPNoPAC = init->m_WarnADHPNoPAC;

	m_WarnADHPNoMatchingPACPresent = init->m_WarnADHPNoMatchingPACPresent;
	m_WarnADHPNoMatchingPAC = init->m_WarnADHPNoMatchingPAC;

	m_WarnNotDefaultServerPresent = init->m_WarnNotDefaultServerPresent;
	m_WarnNotDefaultServer = init->m_WarnNotDefaultServer;

	m_SelectedEAPTypesPresent = init->m_SelectedEAPTypesPresent;
	if (m_SelectedEAPTypesPresent == true)
	{
		status = copy<eap_type_value_e>(
			&(init->m_active_eap_methods),
			&m_active_eap_methods,
			tools,
			false);
		if (status != eap_status_ok)
		{
			return;
		}

		status = copy<eap_type_value_e>(
			&(init->m_disabled_eap_methods),
			&m_disabled_eap_methods,
			tools,
			false);
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_TunnelingTypePresent = init->m_TunnelingTypePresent;
	m_TunnelingType = init->m_TunnelingType;

	m_DestinationIndexAndTypePresent = init->m_DestinationIndexAndTypePresent;
	m_DestinationIndexType = init->m_DestinationIndexType;
	m_DestinationIndex = init->m_DestinationIndex;

	m_MethodInfoPresent = init->m_MethodInfoPresent;
	if (m_MethodInfoPresent == true)
	{
		status = m_KReleaseDate.set_copy_of_buffer(&(init->m_KReleaseDate));
		if (status != eap_status_ok)
		{
			return;
		}

		status = m_KEapTypeVersion.set_copy_of_buffer(&(init->m_KEapTypeVersion));
		if (status != eap_status_ok)
		{
			return;
		}

		status = m_KManufacturer.set_copy_of_buffer(&(init->m_KManufacturer));
		if (status != eap_status_ok)
		{
			return;
		}
	}

	m_ButtonIdPresent = init->m_ButtonIdPresent;
	m_ButtonId = init->m_ButtonId;

	m_ShowPassWordPromptPresent = init->m_ShowPassWordPromptPresent;
	m_ShowPassWordPrompt = init->m_ShowPassWordPrompt;

	m_UseIdentityPrivacyPresent = init->m_UseIdentityPrivacyPresent;
	m_UseIdentityPrivacy = init->m_UseIdentityPrivacy;

	m_completion_status = init->m_completion_status;

	m_is_valid = true;
}

//-------------------------------------------------------------------------------

void eap_method_settings_c::trace() const
{
	u32_t ind = 0ul;

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_is_valid=%d\n"),
		m_is_valid));

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_completion_status=%d\n"),
		m_completion_status));

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_EAPType=0xfe%06x%08x\n"),
		m_EAPType.get_vendor_id(),
		m_EAPType.get_vendor_type()));

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_IndexType=%d\n"),
		m_IndexType));

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_Index=%d\n"),
		m_Index));

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_UseAutomaticCACertificatePresent=%d\n"),
		m_UseAutomaticCACertificatePresent));
	if (m_UseAutomaticCACertificatePresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():  m_UseAutomaticCACertificate=%d\n"),
			m_UseAutomaticCACertificate));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_UseAutomaticUsernamePresent=%d\n"),
		m_UseAutomaticUsernamePresent));
	if (m_UseAutomaticUsernamePresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():  m_UseAutomaticUsername=%d\n"),
			m_UseAutomaticUsername));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_UseAutomaticRealmPresent=%d\n"),
		m_UseAutomaticRealmPresent));
	if (m_UseAutomaticRealmPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():  m_UseAutomaticRealm=%d\n"),
			m_UseAutomaticRealm));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_UsernamePresent=%d\n"),
		m_UsernamePresent));
	if (m_UsernamePresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			get_am_tools(), 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_method_settings_c::trace():     m_Username_fix"),
			m_Username_fix.get_data(),
			m_Username_fix.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_PasswordExistPresent=%d\n"),
		m_PasswordExistPresent));
	if (m_PasswordExistPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_PasswordExist=%d\n"),
			m_PasswordExist));
	}


	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_PasswordPresent=%d\n"),
		m_PasswordPresent));
	if (m_PasswordPresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			get_am_tools(), 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_method_settings_c::trace():     m_Password"),
			m_Password.get_data(),
			m_Password.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_RealmPresent=%d\n"),
		m_RealmPresent));
	if (m_RealmPresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			get_am_tools(), 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_method_settings_c::trace():     m_Realm"),
			m_Realm.get_data(),
			m_Realm.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_UsePseudonymsPresent=%d\n"),
		m_UsePseudonymsPresent));
	if (m_UsePseudonymsPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_UsePseudonyms=%d\n"),
			m_UsePseudonyms));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_VerifyServerRealmPresent=%d\n"),
		m_VerifyServerRealmPresent));
	if (m_VerifyServerRealmPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_VerifyServerRealm=%d\n"),
			m_VerifyServerRealm));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_RequireClientAuthenticationPresent=%d\n"),
		m_RequireClientAuthenticationPresent));
	if (m_RequireClientAuthenticationPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_RequireClientAuthentication=%d\n"),
			m_RequireClientAuthentication));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_SessionValidityTimePresent=%d\n"),
		m_SessionValidityTimePresent));
	if (m_SessionValidityTimePresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_SessionValidityTime=%d\n"),
			m_SessionValidityTime));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_CipherSuitesPresent=%d\n"),
		m_CipherSuitesPresent));
	if (m_CipherSuitesPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_CipherSuites=%d\n"),
			m_CipherSuites.get_object_count()));
		for (ind = 0ul; ind < m_CipherSuites.get_object_count(); ++ind)
		{
			u16_t * cipher_suite = m_CipherSuites.get_object(ind);
			if (cipher_suite != 0)
			{
				EAP_TRACE_DEBUG(
					get_am_tools(),
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_method_settings_c::trace():     cipher_suite=%d\n"),
					*cipher_suite));
			}
		}
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_PEAPVersionsPresent=%d\n"),
		m_PEAPVersionsPresent));
	if (m_PEAPVersionsPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_PEAPv0Allowed=%d\n"),
			m_PEAPv0Allowed));
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_PEAPv1Allowed=%d\n"),
			m_PEAPv1Allowed));
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_PEAPv2Allowed=%d\n"),
			m_PEAPv2Allowed));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_CertificatesPresent=%d\n"),
		m_CertificatesPresent));
	if (m_CertificatesPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_Certificates=%d\n"),
			m_Certificates.get_object_count()));
		for (ind = 0ul; ind < m_Certificates.get_object_count(); ++ind)
		{
			eap_certificate_entry_c * entry = m_Certificates.get_object(ind);
			if (entry != 0)
			{
				entry->trace();
			}
		}
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_EnabledEncapsulatedEAPTypesPresent=%d\n"),
		m_EnabledEncapsulatedEAPTypesPresent));
	if (m_EnabledEncapsulatedEAPTypesPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_EnabledEncapsulatedEAPTypes=%d\n"),
			m_EnabledEncapsulatedEAPTypes.get_object_count()));
		for (ind = 0ul; ind < m_EnabledEncapsulatedEAPTypes.get_object_count(); ++ind)
		{
			eap_type_value_e * type = m_EnabledEncapsulatedEAPTypes.get_object(ind);
			if (type != 0)
			{
				EAP_TRACE_DEBUG(
					get_am_tools(),
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_method_settings_c::trace():     EAP-type=0xfe%06x%08x\n"),
					type->get_vendor_id(),
					type->get_vendor_type()));
			}
		}
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_DisabledEncapsulatedEAPTypesPresent=%d\n"),
		m_DisabledEncapsulatedEAPTypesPresent));
	if (m_DisabledEncapsulatedEAPTypesPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_DisabledEncapsulatedEAPTypes=%d\n"),
			m_DisabledEncapsulatedEAPTypes.get_object_count()));
		for (ind = 0ul; ind < m_DisabledEncapsulatedEAPTypes.get_object_count(); ++ind)
		{
			eap_type_value_e * type = m_DisabledEncapsulatedEAPTypes.get_object(ind);
			if (type != 0)
			{
				EAP_TRACE_DEBUG(
					get_am_tools(),
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_method_settings_c::trace():     EAP-type=0xfe%06x%08x\n"),
					type->get_vendor_id(),
					type->get_vendor_type()));
			}
		}
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_AuthProvModeAllowedPresent=%d\n"),
		m_AuthProvModeAllowedPresent));
	if (m_AuthProvModeAllowedPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_AuthProvModeAllowed=%d\n"),
			m_AuthProvModeAllowed));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_UnauthProvModeAllowedPresent=%d\n"),
		m_UnauthProvModeAllowedPresent));
	if (m_UnauthProvModeAllowedPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_UnauthProvModeAllowed=%d\n"),
			m_UnauthProvModeAllowed));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_PACGroupReferencePresent=%d\n"),
		m_PACGroupReferencePresent));
	if (m_PACGroupReferencePresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			get_am_tools(), 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_method_settings_c::trace():     m_PACGroupReference"),
			m_PACGroupReference.get_data(),
			m_PACGroupReference.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_WarnADHPNoPACPresent=%d\n"),
		m_WarnADHPNoPACPresent));
	if (m_WarnADHPNoPACPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_WarnADHPNoPAC=%d\n"),
			m_WarnADHPNoPAC));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_WarnADHPNoMatchingPACPresent=%d\n"),
		m_WarnADHPNoMatchingPACPresent));
	if (m_WarnADHPNoMatchingPACPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_WarnADHPNoMatchingPAC=%d\n"),
			m_WarnADHPNoMatchingPAC));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_WarnNotDefaultServerPresent=%d\n"),
		m_WarnNotDefaultServerPresent));
	if (m_WarnNotDefaultServerPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_WarnNotDefaultServer=%d\n"),
			m_WarnNotDefaultServer));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_SelectedEAPTypesPresent=%d\n"),
		m_SelectedEAPTypesPresent));
	if (m_SelectedEAPTypesPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_active_eap_methods=%d\n"),
			m_active_eap_methods.get_object_count()));
		for (ind = 0ul; ind < m_active_eap_methods.get_object_count(); ++ind)
		{
			eap_type_value_e * type = m_active_eap_methods.get_object(ind);
			if (type != 0)
			{
				EAP_TRACE_DEBUG(
					get_am_tools(),
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_method_settings_c::trace():         active EAP-type=0xfe%06x%08x\n"),
					type->get_vendor_id(),
					type->get_vendor_type()));
			}
		}
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_disabled_eap_methods=%d\n"),
			m_disabled_eap_methods.get_object_count()));
		for (ind = 0ul; ind < m_disabled_eap_methods.get_object_count(); ++ind)
		{
			eap_type_value_e * type = m_disabled_eap_methods.get_object(ind);
			if (type != 0)
			{
				EAP_TRACE_DEBUG(
					get_am_tools(),
					TRACE_FLAGS_DEFAULT,
					(EAPL("eap_method_settings_c::trace():         disabled EAP-type=0xfe%06x%08x\n"),
					type->get_vendor_id(),
					type->get_vendor_type()));
			}
		}
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_TunnelingTypePresent=%d\n"),
		m_TunnelingTypePresent));
	if (m_TunnelingTypePresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_TunnelingType=0xfe%06x%08x\n"),
			m_TunnelingType.get_vendor_id(),
			m_TunnelingType.get_vendor_type()));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_DestinationIndexAndTypePresent=%d\n"),
		m_DestinationIndexAndTypePresent));
	if (m_DestinationIndexAndTypePresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_DestinationIndexType=%d\n"),
			m_DestinationIndexType));
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_DestinationIndex=%d\n"),
			m_DestinationIndex));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_MethodInfoPresent=%d\n"),
		m_MethodInfoPresent));
	if (m_MethodInfoPresent == true)
	{
		EAP_TRACE_DATA_DEBUG(
			get_am_tools(), 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_method_settings_c::trace():     m_KReleaseDate"),
			m_KReleaseDate.get_data(),
			m_KReleaseDate.get_data_length()));
		EAP_TRACE_DATA_DEBUG(
			get_am_tools(), 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_method_settings_c::trace():     m_KEapTypeVersion"),
			m_KEapTypeVersion.get_data(),
			m_KEapTypeVersion.get_data_length()));
		EAP_TRACE_DATA_DEBUG(
			get_am_tools(), 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("eap_method_settings_c::trace():     m_KManufacturer"),
			m_KManufacturer.get_data(),
			m_KManufacturer.get_data_length()));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_ButtonIdPresent=%d\n"),
		m_ButtonIdPresent));
	if (m_ButtonIdPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_ButtonId=%d\n"),
			m_ButtonId));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_ShowPassWordPromptPresent=%d\n"),
		m_ShowPassWordPromptPresent));
	if (m_ShowPassWordPromptPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_ShowPassWordPrompt=%d\n"),
			m_ShowPassWordPrompt));
	}

	EAP_TRACE_DEBUG(
		get_am_tools(),
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_method_settings_c::trace(): m_UseIdentityPrivacyPresent=%d\n"),
		m_UseIdentityPrivacyPresent));
	if (m_UseIdentityPrivacyPresent == true)
	{
		EAP_TRACE_DEBUG(
			get_am_tools(),
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_method_settings_c::trace():     m_UseIdentityPrivacy=%d\n"),
			m_UseIdentityPrivacy));
	}
}

//-------------------------------------------------------------------------------

// End of file
