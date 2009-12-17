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



#ifndef _EAPTYPE_H_
#define _EAPTYPE_H_

// INCLUDES
#include <e32base.h>
#include <ecom/ecom.h> 

#include <EapSettings.h>

// FORWARD DECLARATIONS
class abs_eap_am_tools_c;
class eap_base_type_c;
class abs_eap_base_type_c;
class CEapTypeInfo;
class eap_am_network_id_c;

#ifndef RD_WLAN_3_1_BACKPORTING
class abs_eap_configuration_if_c;
#endif

// LOCAL DATA
// The UID for EAP plugin interface. ECom uses this.
const TUid KEapTypeInterfaceUid = {0x101f8e4a};

/// Possible services.
enum TIndexType
{
	EDialoutISP,
	EDialinISP,
	EOutgoingGPRS,
	ELan,
	EVpn
};

struct SIapInfo {
	TIndexType indexType;
	TInt index;
}; 

// CLASS DECLARATION

/**
* The base interface class for EAP plug-in access.
* Includes methods to create either the configuration interface or the EAP protocol interface.
*/
class CEapType : public CBase  
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
	inline static CEapType* NewL(const TDesC8& aCue, TIndexType aIndexType, TInt aIndex);	
	
	/**
	* Unloads the implementation DLL.
	*/
	inline virtual ~CEapType();

#ifndef RD_WLAN_3_1_BACKPORTING

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
											   abs_eap_configuration_if_c * const configuration_if) = 0;

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

	/**
	* Invokes the configuration UI. Displays a dialog for configuring the EAP type settings.
	*/
	virtual TInt InvokeUiL() = 0;
	
	/**
	* Gets information about EAP type. 
	* @return Pointer to a class that contains the EAP type information. Also pushed to cleanup stack.
	*/
	virtual CEapTypeInfo* GetInfoLC() = 0;
	
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
	virtual void SetTunnelingType(const TInt aTunnelingType) = 0;
	
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


private:

	/// ECom uses this key to keep track of DLL usage.
	TUid iDtor_ID_Key;
};

#include "EapType.inl"

#endif // _EAPTYPE_H_

// End of file
