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
* Description:  EAP-settings class.
*
*/

/*
* %version: 24 %
*/

#ifndef _EAP_METHOD_SETTINGS_H_
#define _EAP_METHOD_SETTINGS_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_METHOD_SETTINGS_H)
	#define EAP_CLASS_VISIBILITY_EAP_METHOD_SETTINGS_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_METHOD_SETTINGS_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_METHOD_SETTINGS_H 
	#define EAP_FUNC_EXPORT_EAP_METHOD_SETTINGS_H 
	#define EAP_C_FUNC_EXPORT_EAP_METHOD_SETTINGS_H 
#elif defined(EAP_EXPORT_EAP_METHOD_SETTINGS_H)
	#define EAP_CLASS_VISIBILITY_EAP_METHOD_SETTINGS_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_METHOD_SETTINGS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_METHOD_SETTINGS_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_METHOD_SETTINGS_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_METHOD_SETTINGS_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_METHOD_SETTINGS_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_METHOD_SETTINGS_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_METHOD_SETTINGS_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_METHOD_SETTINGS_H 
	#define EAP_C_FUNC_EXPORT_EAP_METHOD_SETTINGS_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_tools.h"
#include "eap_expanded_type.h"
#include "eap_variable_data.h"
#include "eap_array.h"

//-------------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_METHOD_SETTINGS_H eap_certificate_entry_c
{

private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

public:

	eap_certificate_entry_c(
		abs_eap_am_tools_c * const tools);

	virtual ~eap_certificate_entry_c();

	enum eap_certificate_type_e
	{
		eap_certificate_type_none,
		eap_certificate_type_user,
		eap_certificate_type_CA,
	};

	bool get_is_valid();

	bool get_is_valid_data();

	eap_certificate_entry_c * copy();

	void trace() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Specifies whether this entry describes user or CA certificate (mandatory)
	eap_certificate_type_e m_CertType;

	// Subject name in distinguished name ASCII form. This is optional.
	// For example "/C=US/O=Some organization/CN=Some common name".	
	bool m_SubjectNamePresent;
	eap_variable_data_c m_SubjectName;

	// Issuer name in distinguished name ASCII form. This is optional.
	// For example "/C=US/O=Some organization/CN=Some common name".
	bool m_IssuerNamePresent;
	eap_variable_data_c m_IssuerName;

	// Serial number in ASCII form. This is optional.
	bool m_SerialNumberPresent;
	eap_variable_data_c m_SerialNumber;

	// Subject key in binary form. This is mandatory.
	bool m_SubjectKeyIDPresent;
	eap_variable_data_c m_SubjectKeyID;

	// Thumbprint in binary form. This is optional.
	bool m_ThumbprintPresent;
	eap_variable_data_c m_Thumbprint;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// This holds only the certificate label. This is the text UI will show.
	bool m_LabelPresent;
	eap_variable_data_c m_Label;

	// Primary name of the certificate if any, UI uses this.
	bool m_PrimaryNamePresent;
	eap_variable_data_c m_PrimaryName;

	// Secondary name of the certificate if any, UI uses this.
	bool m_SecondaryNamePresent;
	eap_variable_data_c m_SecondaryName;

	// UI uses this to indicate enabled certificate.
	bool m_iIsEnabledPresent;
	bool m_iIsEnabled;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
};

//-------------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_METHOD_SETTINGS_H eap_method_values_c
{

private:

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

protected:

	abs_eap_am_tools_c * get_am_tools() const;

public:

	eap_method_values_c(
		abs_eap_am_tools_c * const tools);

	virtual ~eap_method_values_c();

	bool m_is_valid;

	/// Status of the operation.
	eap_status_e m_completion_status;

	/// Specifies the EAP-method these settings are for. 
	eap_type_value_e m_EAPType;

	/// Specifies the index type (bearer protocol) these settings are for.
	/// Values are ELan or EVpn.
	u32_t m_IndexType;

	/// Specifies unique index in the settings of the bearer protocol.
	u32_t m_Index;

	/// Use automatic Ca certificate.
	bool m_UseAutomaticCACertificatePresent;
	bool m_UseAutomaticCACertificate;

	/// Use automatic username.
	bool m_UseAutomaticUsernamePresent;
	bool m_UseAutomaticUsername;

	/// Use automatic realm.
	bool m_UseAutomaticRealmPresent;
	bool m_UseAutomaticRealm;

	/// Username in ASCII format
	bool m_UsernamePresent;
	eap_variable_data_c m_Username_fix;

	/// Get: Whether password is stored in database.
	/// Set: Whether password must be cleared from database.
	bool m_PasswordExistPresent;
	bool m_PasswordExist;

	/// Password in ASCII format
	bool m_PasswordPresent;
	eap_variable_data_c m_Password;

	/// Realm in ASCII format
	bool m_RealmPresent;
	eap_variable_data_c m_Realm;

	/// Use pseudonym identities in EAP-SIM/AKA
	bool m_UsePseudonymsPresent;
	bool m_UsePseudonyms;

	/// Whether EAP-TLS/TTLS/PEAP should verify server realm
	bool m_VerifyServerRealmPresent;
	bool m_VerifyServerRealm;

	/// Whether EAP-TLS/TTLS/PEAP should require client authentication
	bool m_RequireClientAuthenticationPresent;
	bool m_RequireClientAuthentication;

	/// General session validity time (in minutes)
	bool m_SessionValidityTimePresent;
	u32_t m_SessionValidityTime;

	/// An array of allowed cipher suites for EAP-TLS/TTLS/PEAP. 
	/// Refer to RFC2246 chapter A.5 for the values.
	bool m_CipherSuitesPresent;
	eap_array_c<u16_t> m_CipherSuites;

	/// Which EAP-PEAP versions are allowed
	bool m_PEAPVersionsPresent;
	bool m_PEAPv0Allowed;
	bool m_PEAPv1Allowed;
	bool m_PEAPv2Allowed;

  	/// Array listing the allowed certificates for EAP-TLS/TTLS/PEAP.
  	/// Subject key ID and Certificate type are the only mandatory certificate 
  	/// details needed at the moment.
  	bool m_CertificatesPresent;
	eap_array_c<eap_certificate_entry_c> m_Certificates;

	/// Array listing the allowed encapsulated EAP types (in priority order).
	/// Use EAP type values from eap_type_value_e.
	bool m_EnabledEncapsulatedEAPTypesPresent;
	eap_array_c<eap_type_value_e> m_EnabledEncapsulatedEAPTypes;

	/// Array listing the disabled encapsulated EAP types.
	/// Use EAP type values from eap_type_value_e.
	bool m_DisabledEncapsulatedEAPTypesPresent;
	eap_array_c<eap_type_value_e> m_DisabledEncapsulatedEAPTypes;

	/// Whether Authenticated provisioning mode allowed or not in EAP-FAST.
	bool m_AuthProvModeAllowedPresent;
	bool m_AuthProvModeAllowed;

	/// Whether Unauthenticated provisioning mode allowed or not in EAP-FAST.
	bool m_UnauthProvModeAllowedPresent;
	bool m_UnauthProvModeAllowed;

	/// PAC group reference in ASCII format for EAP-FAST.
	bool m_PACGroupReferencePresent;
	eap_variable_data_c m_PACGroupReference;

	/// Whether to Warn (or Prompt) for ADHP (Authenticated Diffie-Hellman Protocol) 
	/// auto-provisioning when there is no PAC at all. EAP-FAST specific.
	bool m_WarnADHPNoPACPresent;
	bool m_WarnADHPNoPAC;

	/// Whether to Warn (or Prompt) for ADHP auto-provisioning when 
	/// there is no PAC that matches the A-ID sent by server. EAP-FAST specific.
	bool m_WarnADHPNoMatchingPACPresent;
	bool m_WarnADHPNoMatchingPAC;

	/// Whether to Warn (or Prompt) when client encouters a server that has provisioned 
	/// the client with a PAC before but is not currently selected as the default server. 
	/// EAP-FAST specific.
	bool m_WarnNotDefaultServerPresent;
	bool m_WarnNotDefaultServer;

	// Array listing the active and disabled EAP types (in priority order).
	// Use EAP type values from eap_type_value_e.
	bool m_SelectedEAPTypesPresent;
	eap_array_c<eap_type_value_e> m_active_eap_methods;
	eap_array_c<eap_type_value_e> m_disabled_eap_methods;

	bool m_TunnelingTypePresent;
	eap_type_value_e m_TunnelingType;

	bool m_DestinationIndexAndTypePresent;
	u32_t m_DestinationIndexType;
	u32_t m_DestinationIndex;

	bool m_MethodInfoPresent;
	eap_variable_data_c m_KReleaseDate;
	eap_variable_data_c m_KEapTypeVersion;
	eap_variable_data_c m_KManufacturer;

	bool m_ButtonIdPresent; // JPH: remove this
	i32_t m_ButtonId; // JPH: remove this

	bool m_ShowPassWordPromptPresent;
	bool m_ShowPassWordPrompt;

	bool m_UseIdentityPrivacyPresent;
	bool m_UseIdentityPrivacy;

};

//-------------------------------------------------------------------------------

class EAP_CLASS_VISIBILITY_EAP_METHOD_SETTINGS_H eap_method_settings_c
: public eap_method_values_c
{
public:

	eap_method_settings_c(
		abs_eap_am_tools_c * const tools);

	eap_method_settings_c(
		abs_eap_am_tools_c * const tools,
		const eap_method_settings_c * const init);

	virtual ~eap_method_settings_c();

	void trace() const;

};

//-------------------------------------------------------------------------------

#if defined(USE_EAP_TRACE)

	#define EAP_TRACE_METHOD_SETTINGS(settings) { (settings)->trace(); }

#else

	#define EAP_TRACE_METHOD_SETTINGS(settings)

#endif //#if defined(USE_EAP_TRACE)


//-------------------------------------------------------------------------------

#endif //#ifndef _EAP_METHOD_SETTINGS_H_

// End of file
