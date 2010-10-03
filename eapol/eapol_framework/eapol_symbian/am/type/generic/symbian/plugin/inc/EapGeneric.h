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
* Description:  Class implements the generic EAP type interface.
*
*/

/*
* %version: 36 %
*/

#ifndef _EAP_GENERIC_H_
#define _EAP_GENERIC_H_

// INCLUDES
#include <EapType.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPGENERIC_H)
	#define EAP_CLASS_VISIBILITY_EAPGENERIC_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPGENERIC_H 
	#define EAP_C_FUNC_VISIBILITY_EAPGENERIC_H 
	#define EAP_FUNC_EXPORT_EAPGENERIC_H 
	#define EAP_C_FUNC_EXPORT_EAPGENERIC_H 
#elif defined(EAP_EXPORT_EAPGENERIC_H)
	#define EAP_CLASS_VISIBILITY_EAPGENERIC_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPGENERIC_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPGENERIC_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPGENERIC_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPGENERIC_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPGENERIC_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPGENERIC_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPGENERIC_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPGENERIC_H 
	#define EAP_C_FUNC_EXPORT_EAPGENERIC_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_header.h"
#include "eap_array.h"
#include "abs_eap_plugin_message.h"
#include "EapClientIf.h"

// FORWARD DECLARATIONS
class eap_am_network_id_c;
class eap_method_settings_c;
class abs_eap_am_tools_c;
class eap_certificate_entry_c;
class eap_plugin_message_base_c;


enum eap_generic_wait_state_e
{
	eap_generic_wait_state_none,
	eap_generic_wait_state_complete_get_configuration,
	eap_generic_wait_state_complete_set_configuration,
	eap_generic_wait_state_complete_delete_configuration,
	eap_generic_wait_state_complete_copy_configuration,
	eap_generic_wait_state_complete_get_type_info,
	eap_generic_wait_state_complete_invoke_ui,
	eap_generic_wait_state_complete_set_index,
};

const TUint KMaxStringLength = 64;

// CLASS DECLARATION
/**
* Class implements the generic EAP type interface.
*/
class EAP_CLASS_VISIBILITY_EAPGENERIC_H CEapGeneric
: public CEapType
, public abs_eap_plugin_message_c
, public EapClientIf
{
public:		

	/**
	* Construction function. Called by ECom after the EAP generic plugin has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	static CEapGeneric* NewL(SIapInfo* aIapInfo);	

	/**
	* Destructor does nothing.
	*/
	virtual ~CEapGeneric();
	
	/**
	* Creates EAP protocol interface implementation. Instances an object that
	* has been derived from eap_base_type_c that handles the communication 
	* with EAP stack. 
	* @param aTools Pointer to tools class.
	* @param aPartner Used for callbacks to the stack.
	* @param is_client_when_true Specifies whether the EAP type acts as a client or server.
	* @param receive_network_id Network addresses
	* @param eap_config_if Pointer used for call back to creater of stack (eapol_am_wlan_authentication_symbian_c class).
	* @return Pointer to the implementation.
	*/		
	virtual eap_base_type_c* GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											   abs_eap_base_type_c* const aPartner,
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id,
											   abs_eap_configuration_if_c * const configuration_if);
	


	/**
	* Gets information about EAP type. 
	* @return Pointer to a class that contains the EAP type information. Also pushed to cleanup stack.
	*/
	CEapTypeInfo* GetInfoL();

	/**
	* Deletes EAP type configuration
	*/	
	void DeleteConfigurationL();

	/**
	* Returns the version of the interface that the EAP type implements.
	* The client-side of the interface must always check the version with this function 
	* and not call the functions that are not implemented. New functions must be
	* added to the end of the interface so that the order of the old functions
	* does not change.
	* @return Integer indicating the version.
	*/
	TUint GetInterfaceVersion();

	/**
	* Sets the tunneling type. This is used to indicate that this type is run inside another 
	* EAP type. 
	* @param aTunnelingType Type number for the tunneling type
	*/	
	void SetTunnelingType(const TEapExpandedType aTunnelingType);

	/**
	* Changes the index of the saved parameters.
	* @param aIndexType Indicates the bearer used for this connection.
	* @param aIndex Index for the connection. aIndexType and aIndex uniquely specify the connection.
	* @return Pointer to the implementation.
	*/
	void SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex );
		
	/**
	* Sets the EAP types configuration
	* @param aSettings Structure containing the settings
	*/
	void SetConfigurationL(const EAPSettings& aSettings);

	/**
	* Gets the EAP types configuration
	* @param aSettings Structure containing the settings
	*/
	void GetConfigurationL(EAPSettings& aSettings);

	/**
	* Copies the EAP types configuration
	* @param aDestinationIndex ID to where copy the settings.
	*/
	void CopySettingsL(const TIndexType aDestinationIndexType, const TInt aDestinationIndex);

	eap_status_e complete_get_configuration(
		const eap_method_settings_c * const internal_settings);

	eap_status_e complete_set_configuration(
		const eap_status_e completion_status);

	eap_status_e complete_delete_configuration(
		const eap_status_e completion_status);

	eap_status_e complete_copy_configuration(
		const eap_status_e completion_status);

	eap_status_e complete_set_index(
		const eap_status_e completion_status);

	eap_status_e complete_get_type_info(
		const eap_method_settings_c * const internal_settings);

	eap_status_e complete_invoke_ui(
		const eap_method_settings_c * const internal_settings);

protected:

	/**
	* Constructor initialises member variables.
	*/
	CEapGeneric(
		const TIndexType aIndexType,
		const TInt aIndex,
		const TEapExpandedType aEapType);

	void ConstructL();

private:

	void Activate();

	void Complete();

	void WaitCompletion();

	void SetCompletionStatusIfStillOk(const eap_status_e status);

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	eap_plugin_message_base_c * const m_server;

	CActiveSchedulerWait iWait;

	// Bearer type
	TIndexType iIndexType;

	// Unique index
	TInt iIndex;

	TEapExpandedType iEapType;

	// Tunneling type
	eap_type_value_e iTunnelingType;
	bool iTunnelingTypePresent;

	eap_generic_wait_state_e iWaitState;

	eap_status_e iCompletionStatus;

	TRequestStatus iAsyncronousStatus;



	TBuf<KMaxStringLength> iReleaseDate;
	TBuf<KMaxStringLength> iEapTypeVersion;
	TBuf<KMaxStringLength> iManufacturer;

	EAPSettings * ipEAPSettings;
};

#endif // _EAP_GENERIC_H_

// End of file
