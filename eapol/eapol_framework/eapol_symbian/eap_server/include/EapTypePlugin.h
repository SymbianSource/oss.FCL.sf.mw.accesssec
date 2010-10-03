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
* %version: 13 %
*/

#ifndef _EAP_TYPE_PLUGIN_H_
#define _EAP_TYPE_PLUGIN_H_

// INCLUDES
#include <e32base.h>
#include <ecom/ecom.h> 

#include <EapSettings.h>
#include <EapTypeDefinitions.h>

// FORWARD DECLARATIONS
class abs_eap_am_tools_c;
class eap_base_type_c;
class abs_eap_base_type_c;
class CEapTypeInfo;
class eap_am_network_id_c;

#ifndef RD_WLAN_3_1_BACKPORTING
class abs_eap_configuration_if_c;
#endif

class AbsPacStoreInitializer;

struct SPluginInfo
{
	TIndexType indexType;
	TInt index;
	TEapExpandedType aEapType;
	abs_eap_am_tools_c * aTools;
}; 

// CLASS DECLARATION

/**
* The interface class for direct EAP plug-in access.
* Includes methods to create either the configuration interface or the EAP protocol interface.
*/
class CEapTypePlugin
: public CBase
{
public:

	/**
	* Factory function that loads the EAP type implementation DLL (plug-in).
	* Uses ECom architecture to load the correct EAP type DLL. Calls the initialization
	* function of the EAP type
	* @param aCue EAP type id that specifies which plugin is loaded.
	* @param aIndexType Indicates the bearer used for this connection.
	* @param aIndex Index for the connection. aIndexType and aIndex uniquely specify the connection.
	* @return Pointer to the implementation.
	*/
	inline static CEapTypePlugin* NewL(const TDesC8& aCue, TIndexType aIndexType, TInt aIndex, abs_eap_am_tools_c * const aTools);	

	/**
	* Unloads the implementation DLL.
	*/
	inline virtual ~CEapTypePlugin();

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
	virtual eap_base_type_c* GetStackInterfaceL(abs_eap_am_tools_c * const aTools, 
											   abs_eap_base_type_c * const aPartner,
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id,
											   abs_eap_configuration_if_c * const configuration_if) = 0;

#if 0
#ifndef RD_WLAN_3_1_BACKPORTING

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

	virtual eap_base_type_c* GetStackInterfaceL(abs_eap_am_tools_c* const aTools, 
											   abs_eap_base_type_c* const aPartner,
											   const bool is_client_when_true,
											   const eap_am_network_id_c * const receive_network_id) = 0;
	
#endif // #ifndef RD_WLAN_3_1_BACKPORTING
#endif


	
	/**
	* Gets information about EAP type. 
	* @return Pointer to a class that contains the EAP type information. Also pushed to cleanup stack.
	*/
	virtual CEapTypeInfo* GetInfoL() = 0;
	
	/**
	* Deletes EAP type configuration
	*/	
	virtual void DeleteConfigurationL() = 0;

	/**
	* Returns the version of the interface that the EAP type implements.
	* The client-side of the interface must always check the version with this function 
	* and not call the functions that are not implemented. New functions must be
	* added to the end of the interface so that the order of the old functions
	* does not change.
	* @return Integer indicating the version.
	*/
	virtual TUint GetInterfaceVersion() = 0;

	/**
	* Parses the opaque_data field in CImplementationInformation and returns true if
	* string NOT_OUTSIDE_PEAP is found.
	* @param aImplInfo Implementation info returned by ListImplementations call
	* @return Boolean
	*/
	inline static TBool IsDisallowedOutsidePEAP(const CImplementationInformation& aImplInfo);

	/**
	* Parses the opaque_data field in CImplementationInformation and returns true if
	* string NOT_INSIDE_PEAP is found.
	* @param aImplInfo Implementation info returned by ListImplementations call
	* @return Boolean
	*/	
	inline static TBool IsDisallowedInsidePEAP(const CImplementationInformation& aImplInfo);

	/**
	* Parses the opaque_data field in CImplementationInformation and returns true if
	* string NOT_INSIDE_TTLS is found.
	* @param aImplInfo Implementation info returned by ListImplementations call
	* @return Boolean
	*/	
	inline static TBool IsDisallowedInsideTTLS(const CImplementationInformation& aImplInfo);

	/**
	* Sets the tunneling type. This is used to indicate that this type is run inside another 
	* EAP type. 
	* @param aTunnelingType Type number for the tunneling type
	*/	
	virtual void SetTunnelingType(const TEapExpandedType aTunnelingType) = 0;
	
	/**
	* Changes the index of the saved parameters.
	* @param aIndexType Indicates the bearer used for this connection.
	* @param aIndex Index for the connection. aIndexType and aIndex uniquely specify the connection.
	*/
	virtual void SetIndexL(
		const TIndexType aIndexType, 
		const TInt aIndex) = 0;

	/**
	* Sets the EAP types configuration
	* @param aSettings Structure containing the settings
	*/
	virtual void SetConfigurationL(const EAPSettings& aSettings) = 0;

	/**
	* Gets the EAP types configuration
	* @param aSettings Structure containing the settings
	*/
	virtual void GetConfigurationL(EAPSettings& aSettings) = 0;
	
	/**
	* Copies the EAP types configuration
	* @param aDestinationIndexType index type of the destination, ELan for WLAN.
	* @param aDestinationIndex ID to where copy the settings.
	*/
	virtual void CopySettingsL(
		const TIndexType aDestinationIndexType, 
		const TInt aDestinationIndex) = 0;

	virtual TInt InitialisePacStore(AbsPacStoreInitializer * const initializer) = 0;

private:

	/// ECom uses this key to keep track of DLL usage.
	TUid iDtor_ID_Key;
};

#include "EapTypePlugin.inl"

#endif // _EAP_TYPE_PLUGIN_H_

// End of file
