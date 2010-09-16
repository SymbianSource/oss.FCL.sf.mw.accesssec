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
* %version: 38 %
*/

#ifndef _EAPTLSPEAP_H_
#define _EAPTLSPEAP_H_

// INCLUDES
#include <EapTypePlugin.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPTLSPEAP_H)
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAP_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAP_H 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAP_H 
	#define EAP_FUNC_EXPORT_EAPTLSPEAP_H 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAP_H 
#elif defined(EAP_EXPORT_EAPTLSPEAP_H)
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAP_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAP_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAP_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPTLSPEAP_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAP_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPTLSPEAP_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPTLSPEAP_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPTLSPEAP_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPTLSPEAP_H 
	#define EAP_C_FUNC_EXPORT_EAPTLSPEAP_H 
#endif
// End: added by script change_export_macros.sh.
#if defined(USE_FAST_EAP_TYPE)
	#include "tls_application_eap_fast.h"
	#include "PacStoreInitialization.h"
	#include "AbsPacStoreInitializer.h"
#else
	class AbsPacStoreInitializer;
#endif
#include "eap_header.h"
#include "abs_eap_base_timer.h"

// CLASS DECLARATION
/**
* Class that implements the generic EAP type interface. Implements EAP TLS protocol.
*/
class EAP_CLASS_VISIBILITY_EAPTLSPEAP_H CEapTlsPeap
: public CEapTypePlugin
#if defined(USE_FAST_EAP_TYPE)
, public abs_pac_store_initializer_c
#endif //#if defined(USE_FAST_EAP_TYPE)
, public abs_eap_base_timer_c
{
public:		

	/**
	* Construction function for TLS. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	static CEapTlsPeap* NewTlsL(SPluginInfo *aIapInfo);

	/**
	* Construction function for PEAP. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	static CEapTlsPeap* NewPeapL(SPluginInfo *aIapInfo);

	/**
	* Construction function for TTLS. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
#if defined(USE_TTLS_EAP_TYPE)
	static CEapTlsPeap* NewTtlsL(SPluginInfo *aIapInfo);
#endif // #if defined(USE_TTLS_EAP_TYPE)

	/**
	* Construction function for TTLS-PAP.
	* 
	* Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information
	*                 about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	
	static CEapTlsPeap* NewTtlsPapL( SPluginInfo* aIapInfo );
	
	/**
	* Construction function for FAST. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
#if defined(USE_FAST_EAP_TYPE)
	static CEapTlsPeap* NewFastL(SPluginInfo *aIapInfo);
#endif

	/**
	* Destructor does nothing.
	*/
	virtual ~CEapTlsPeap();

#ifdef USE_EAP_SIMPLE_CONFIG

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
	
#else
	
	/**
	* Creates EAP protocol interface implementation. Instances an object that
	* has been derived from eap_base_type_c that handles the communication 
	* with EAP stack. 
	* @param aTools Pointer to tools class.
	* @param aPartner Used for callbacks to the stack.
	* @param is_client_when_true Specifies whether the EAP type acts as a client or server.
	* @param receive_network_id Network addresses
	* @return Pointer to the implementation.
	*/
	eap_base_type_c* GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
									   abs_eap_base_type_c* const aPartner,
									   const bool is_client_when_true,
									   const eap_am_network_id_c * const receive_network_id);
	
#endif // #ifdef USE_EAP_SIMPLE_CONFIG
	

	
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
	*/
	void SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex);
		
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

	TInt InitialisePacStore(AbsPacStoreInitializer * const initializer);

#if defined(USE_FAST_EAP_TYPE)

	eap_status_e complete_start_initialize_PAC_store(
		const eap_fast_completion_operation_e completion_operation,
		const eap_fast_initialize_pac_store_completion_e completion);

#endif //#if defined(USE_FAST_EAP_TYPE)

	eap_status_e timer_expired(
		const u32_t id, void *data);

	eap_status_e timer_delete_data(
		const u32_t id, void *data);

protected:
	
	/**
	* Constructor initialises member variables.
	*/
	CEapTlsPeap(const TIndexType aIndexType, const TInt aIndex, const eap_type_value_e aEapType, abs_eap_am_tools_c * const aTools);

private:

#ifdef USE_PAC_STORE

	void UpdatePacStoreCleanupTableL(const TIndexType aIndexType,
		const TInt aIndex, 
		const eap_type_value_e aTunnelingType);
	
#endif // #ifdef USE_PAC_STORE	

	void ConstructL();

private:

	// Bearer type
	TIndexType iIndexType;
	
	// Unique index
	TInt iIndex;
	
	// Eap type (PEAP or TLS or TTLS or FAST)
	eap_type_value_e iEapType;

	// Tunneling type
	eap_type_value_e iTunnelingType;
	
	// EAP array for deleting and changing index
	RImplInfoPtrArray iEapArray;

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * m_am_tools;
	
#if defined(USE_FAST_EAP_TYPE)

	CPacStoreInitialization * iPacStoreInitialization;

	AbsPacStoreInitializer * iInitializer;

#endif //#if defined(USE_FAST_EAP_TYPE)

};

#endif // _EAPTLSPEAP_H_

// End of file
