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
* Description:  This is implementation of CEapGeneralSettings interface.
*
*/

/*
* %version: 29 %
*/

#ifndef _EAP_GENERAL_SETTINGS_IMPL_H_
#define _EAP_GENERAL_SETTINGS_IMPL_H_

// INCLUDES
#include <EapType.h>
#include <EapGeneralSettings.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPGENERALSETTINGSIMPL_H)
	#define EAP_CLASS_VISIBILITY_EAPGENERALSETTINGSIMPL_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPGENERALSETTINGSIMPL_H 
	#define EAP_C_FUNC_VISIBILITY_EAPGENERALSETTINGSIMPL_H 
	#define EAP_FUNC_EXPORT_EAPGENERALSETTINGSIMPL_H 
	#define EAP_C_FUNC_EXPORT_EAPGENERALSETTINGSIMPL_H 
#elif defined(EAP_EXPORT_EAPGENERALSETTINGSIMPL_H)
	#define EAP_CLASS_VISIBILITY_EAPGENERALSETTINGSIMPL_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPGENERALSETTINGSIMPL_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPGENERALSETTINGSIMPL_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPGENERALSETTINGSIMPL_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPGENERALSETTINGSIMPL_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPGENERALSETTINGSIMPL_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPGENERALSETTINGSIMPL_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPGENERALSETTINGSIMPL_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPGENERALSETTINGSIMPL_H 
	#define EAP_C_FUNC_EXPORT_EAPGENERALSETTINGSIMPL_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_header.h"
#include "eap_array.h"
#include "abs_eap_general_settings_message.h"
#include "eap_configuration_field.h"
#include "EapExpandedType.h"
#include "EapClientIf.h"

// FORWARD DECLARATIONS
class eap_am_network_id_c;
class eap_method_settings_c;
class abs_eap_am_tools_c;
class eap_general_settings_message_c;


enum eap_general_settings_wait_state_e
{
	eap_general_settings_wait_state_none,
	eap_general_settings_wait_state_complete_set_eap_methods,
	eap_general_settings_wait_state_complete_get_eap_methods,
	eap_general_settings_wait_state_complete_get_certificate_lists,
	eap_general_settings_wait_state_complete_delete_all_eap_settings,
	eap_general_settings_wait_state_complete_copy_all_eap_settings,
};


// CLASS DECLARATION
/**
* This is implementation of CEapGeneralSettings interface.
*/
class EAP_CLASS_VISIBILITY_EAPGENERALSETTINGSIMPL_H CEapGeneralSettingsImpl
: public CEapGeneralSettings
, public abs_eap_general_settings_message_c
, public EapClientIf
{
public:		

	/**
	* Construction function. Called by ECom after the EAP generic plugin has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	static CEapGeneralSettingsImpl* NewL(SIapInfo* aIapInfo);

	/**
	* Destructor does nothing.
	*/
	virtual ~CEapGeneralSettingsImpl();
	
	/**
	* Returns the version of the interface that the EAP type implements.
	* The client-side of the interface must always check the version with this function 
	* and not call the functions that are not implemented. New functions must be
	* added to the end of the interface so that the order of the old functions
	* does not change.
	* @return Integer indicating the version.
	*/
	TUint GetInterfaceVersion();

	TInt SetEapMethods(
		const RArray<TEapExpandedType> & aActiveEapMethods,
		const RArray<TEapExpandedType> & aDisabledEapMethods);

	TInt GetEapMethods(
		RArray<TEapExpandedType> & aActiveEapMethods,
		RArray<TEapExpandedType> & aDisabledEapMethods);

	TInt GetCertificateLists(
		RPointerArray<EapCertificateEntry> & aUserCerts,
		RPointerArray<EapCertificateEntry> & aCACerts);

	TInt DeleteAllEapSettings();

	TInt CopyAllEapSettings(
		const TIndexType aDestinationIndexType,
		const TInt aDestinationIndex);

	eap_status_e complete_get_eap_methods(
		const eap_method_settings_c * const internal_settings);

	eap_status_e complete_set_eap_methods(
		const eap_status_e completion_status);

	eap_status_e complete_get_certificate_lists(
		const eap_method_settings_c * const internal_settings);

	eap_status_e complete_delete_all_eap_settings(
		const eap_status_e completion_status);

	eap_status_e complete_copy_all_eap_settings(
		const eap_status_e completion_status);

protected:

	/**
	* Constructor initialises member variables.
	*/
	CEapGeneralSettingsImpl(const TIndexType aIndexType, const TInt aIndex);

	void ConstructL();

private:

	void Activate();
	
	void Complete();

	void WaitCompletion();

	void SetCompletionStatusIfStillOk(const eap_status_e status);

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	eap_general_settings_message_c * const m_server;

	CActiveSchedulerWait iWait;

	// Bearer type
	TIndexType iIndexType;

	// Unique index in the bearer space.
	TInt iIndex;

	RArray<TEapExpandedType> * iActiveEapMethods;
	RArray<TEapExpandedType> * iDisabledEapMethods;

	RPointerArray<EapCertificateEntry> * iUserCerts;
	RPointerArray<EapCertificateEntry> * iCACerts;

	eap_general_settings_wait_state_e iWaitState;

	eap_status_e iCompletionStatus;

	TRequestStatus iAsyncronousStatus;
};

#endif // _EAP_GENERAL_SETTINGS_IMPL_H_

// End of file
