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
* %version: 34 %
*/

#ifndef _EAPTYPE_H_
#define _EAPTYPE_H_

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

// CLASS DECLARATION

/**
* The base interface class for EAP plug-in access.
* Includes methods to create either the configuration interface or the EAP protocol interface.
*/
class CEapType
: public CBase
{
public:

    /**
    * Factory function that loads the Generic EAP type implementation DLL (plug-in).
    * @param aIndexType Indicates the bearer used for this connection.
    * @param aIndex Index for the connection. aIndexType and aIndex uniquely specify the connection.
    * @return Pointer to the implementation.
    */
	inline static CEapType* NewL(const TIndexType aIndexType, const TInt aIndex, const TEapExpandedType aEapType);

	/**
	* Unloads the implementation DLL.
	*/
	inline virtual ~CEapType();



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


private:

	/// ECom uses this key to keep track of DLL usage.
	TUid iDtor_ID_Key;
};

#include "EapType.inl"

#endif // _EAPTYPE_H_

// End of file
