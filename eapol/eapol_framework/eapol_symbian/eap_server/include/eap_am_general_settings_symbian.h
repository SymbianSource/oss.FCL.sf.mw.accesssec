/*
* Copyright (c) 2009-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 27 %
*/

#if !defined(_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H_)
#define _EAP_AM_GENERAL_SETTINGS_SYMBIAN_H_

#include "eap_tools.h"
#include "eap_status.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H 
	#define EAP_FUNC_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H 
#elif defined(EAP_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H)
	#define EAP_CLASS_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H 
	#define EAP_C_FUNC_EXPORT_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_expanded_type.h"
#include "eap_array.h"
#include "eap_database_reference_if.h"
#include "eap_am_general_settings.h"
#include "eap_process_tlv_message_data.h"
#include <d32dbms.h>
#include <AbsEapCertificateFetcher.h>
#include <implementationinformation.h>

class eap_method_settings_c;
class CEapTlsPeapCertFetcher;

/** @file */

/// This class is the common part of EAP message interface.
/// This class is interface to the message creation and parsing function.
class EAP_CLASS_VISIBILITY_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H eap_am_general_settings_symbian_c
: public eap_am_general_settings_c
, public CAbsEapCertificateFetcher
{

public:

	// ----------------------------------------------------------------------

	eap_am_general_settings_symbian_c(
		abs_eap_am_tools_c * const tools,
		abs_eap_am_general_settings_c * const partner);

	eap_am_general_settings_symbian_c(
		abs_eap_am_tools_c * const tools);

	virtual ~eap_am_general_settings_symbian_c();

	bool get_is_valid();

	// This is documented in abs_eap_stack_interface_c::configure().
	eap_status_e configure();

	// This is documented in abs_eap_stack_interface_c::shutdown().
	eap_status_e shutdown();

	eap_status_e get_eap_methods(const eap_method_settings_c * const internal_settings);

	eap_status_e set_eap_methods(const eap_method_settings_c * const internal_settings);

	eap_status_e get_certificate_lists(const eap_method_settings_c * const internal_settings);

	eap_status_e delete_all_eap_settings(const eap_method_settings_c * const internal_settings);

	eap_status_e copy_all_eap_settings(const eap_method_settings_c * const internal_settings);


	void CompleteReadCertificatesL(
		const RPointerArray<EapCertificateEntry>& aUserCerts, 
		const RPointerArray<EapCertificateEntry>& aCACerts);

	// This function reads synchronously enabled and disabled EAP-methods from database.
	// This function is used only by EAP-SERVER directly.
	// Use constructor without partner parameter.
	eap_status_e read_eap_methods_synchronously(
		const TUint indexType,
		const TUint index,
		eap_array_c<eap_type_value_e> * const aEnabledEapMethodsArray,
		eap_array_c<eap_type_value_e> * const aDisabledEapMethodsArray);

	// ----------------------------------------------------------------------

private:

	// ----------------------------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	abs_eap_am_general_settings_c * m_partner;

	bool m_is_valid;

	/// Function shutdown() is called already.
	bool m_shutdown_was_called;

	RDbNamedDatabase iGeneralSettingsDb;
	RFs iGeneralSettingsFileServerSession;	

	TBool iGeneralSettingsDbCreated;
	TBool iGeneralSettingsSessionOpened;

	CEapTlsPeapCertFetcher * iCertificateFetcher;

	/// Status of the operation.
	eap_status_e m_completion_status;

	/// Specifies the EAP-method these settings are for. 
	eap_type_value_e m_EAPType;

	/// Specifies the index type (bearer protocol) these settings are for.
	/// Values are ELan or EVpn.
	u32_t m_IndexType;

	/// Specifies unique index in the settings of the bearer protocol.
	u32_t m_Index;

	// ----------------------------------------------------------------------

	void CloseGeneralSettings();

	void OpenGeneralSettingsL();

	void CreateGeneralSettingsL();

	void GetGeneralSettingsLongBinaryL(
		RDbView &aViev,
		const TDesC &aColName,
		HBufC8** const aMethods);

	void GetGeneralSettingsDataL(
		const TUint indexType,
		const TUint index,
		HBufC8** const aEnabledEapMethods,
		HBufC8** const aDisabledEapMethods);


	void SetGeneralSettingsLongBinaryL(
		RDbView &aViev,
		const TDesC &aColName,
		const TDesC8& aMethods);

	void SetGeneralSettingsDataL(
		const TUint indexType,
		const TUint index,
		const TDesC8& aEnabledEapMethods,
		const TDesC8& aDisabledEapMethods);

	void DeleteGeneralSettingsDataL(
		const TUint indexType,
		const TUint index);

	void CopyGeneralSettingsDataL(
		const TUint aSourceIndexType,
		const TUint aSourceIndex,
		const TUint aDestinationIndexType,
		const TUint aDestinationIndex);

	eap_status_e error_complete(
		const eap_status_e completion_status,
		const eap_method_settings_c * const internal_settings,
		const eap_tlv_message_type_function_e error_completion_function);

	eap_status_e filter_eap_methods(
		eap_array_c<eap_type_value_e> * const disabled_eap_methods,
		RPointerArray<TEapExpandedType> * const aPlugins);

	// ----------------------------------------------------------------------
};

#endif //#if !defined(_EAP_AM_GENERAL_SETTINGS_SYMBIAN_H_)


//--------------------------------------------------
// End
