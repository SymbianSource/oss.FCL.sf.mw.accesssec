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
* %version: 17.1.2 %
*/

#ifndef _EAPTLSPEAP_H_
#define _EAPTLSPEAP_H_

// INCLUDES
#include <EapType.h>
#include "eap_header.h"

// CLASS DECLARATION
/**
* Class that implements the generic EAP type interface. Implements EAP TLS protocol.
*/
class CEapTlsPeap : public CEapType
{
public:		

	/**
	* Construction function for TLS. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	static CEapTlsPeap* NewTlsL(SIapInfo *aIapInfo);

	/**
	* Construction function for PEAP. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	static CEapTlsPeap* NewPeapL(SIapInfo *aIapInfo);

	/**
	* Construction function for TTLS. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
#if defined(USE_TTLS_EAP_TYPE)
	static CEapTlsPeap* NewTtlsL(SIapInfo *aIapInfo);
#endif // #if defined(USE_TTLS_EAP_TYPE)

	/**
	* Construction function for TTLS-PAP.
	* 
	* Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information
	*                 about bearer type and unique index.
	* @return Pointer to the instance.
	*/
	
	static CEapTlsPeap* NewTtlsPapL( SIapInfo* aIapInfo );
	
	/**
	* Construction function for FAST. Called by ECom after the DLL has been loaded.
	* @param aIapInfo Pointer to the class that contains information about bearer type and unique index.
	* @return Pointer to the instance.
	*/
#if defined(USE_FAST_EAP_TYPE)
	static CEapTlsPeap* NewFastL(SIapInfo *aIapInfo);
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
	* Invokes the configuration UI.
	**/
	TInt InvokeUiL();
	
	/**
	* Gets information about EAP type. 
	* @return Pointer to a class that contains the EAP type information. Also pushed to cleanup stack.
	*/
	CEapTypeInfo* GetInfoLC();
	
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
	void SetTunnelingType(const TInt aTunnelingType);

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

protected:
	
	/**
	* Constructor initialises member variables.
	*/
	CEapTlsPeap(const TIndexType aIndexType, const TInt aIndex, const eap_type_value_e aEapType);
	
private:

#ifdef USE_PAC_STORE

	void UpdatePacStoreCleanupTableL(const TIndexType aIndexType,
		const TInt aIndex, 
		const eap_type_value_e aTunnelingType);
	
#endif // #ifdef USE_PAC_STORE	

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
};

#endif // _EAPTLSPEAP_H_

// End of file
