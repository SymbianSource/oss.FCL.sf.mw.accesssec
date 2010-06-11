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
* Description:  Class is interface to the generic EAP type.
*
*/

/*
* %version: 14 %
*/

#ifndef _EAP_GENERAL_SETTINGS_H_
#define _EAP_GENERAL_SETTINGS_H_

// INCLUDES
#include <EapType.h>
#include <EapExpandedType.h>

// FORWARD DECLARATIONS

// CLASS DECLARATION
/**
* Class is interface to the generic EAP type.
*/
class CEapGeneralSettings
: public CBase
{
public:

	/**
	* Construction function. Called by ECom after the EAP generic plugin has been loaded.
	* @param aIndexType is the bearer type, ELan for WLAN and EVpn for VPN.
	* @param aIndex is the WLAN service ID for WLAN bearer type and IAP id for VPN. Each bearer must use same aIndex for configuration and authentication.
	* @return Pointer to the instance.
	*/
	inline static CEapGeneralSettings* NewL(
		const TIndexType aIndexType,	
		const TInt aIndex);

	/**
	* Destructor does nothing.
	*/
	inline virtual ~CEapGeneralSettings();
	
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
	 * Function sets the active and disabled EAP-methods.
	 * @param aActiveEapMethods includes a list of enabled EAP-methods. This list can be empty
	 * @param aDisabledEapMethods includes a list of disabled EAP-methods. This list can be empty.
	 */
	virtual TInt SetEapMethods(
		const RArray<TEapExpandedType> & aActiveEapMethods,
		const RArray<TEapExpandedType> & aDisabledEapMethods) = 0;

	/**
	 * Function gets the active and disabled EAP-methods.
	 * @param aActiveEapMethods includes a list of enabled EAP-methods. This list can be empty
	 * @param aDisabledEapMethods includes a list of disabled EAP-methods. This list can be empty.
	 */
	virtual TInt GetEapMethods(
		RArray<TEapExpandedType> & aActiveEapMethods,
		RArray<TEapExpandedType> & aDisabledEapMethods) = 0;

	/**
	 * Function gets the all installed certificates.
	 * @param aUserCerts includes a list of user certificates. This list can be empty.
	 * @param aCACerts includes a list of CA root certificates. This list can be empty.
	 */
	virtual TInt GetCertificateLists(
		RPointerArray<EapCertificateEntry> & aUserCerts,
		RPointerArray<EapCertificateEntry> & aCACerts) = 0;

	/**
	 * Function deletes all settings of the IAP, a pair (aIndexType, aIndex) of NewL() function selects the deleted items.
	 */
	virtual TInt DeleteAllEapSettings() = 0;

	/**
	 * Function copies all settings of the IAP to destination.
	 * A pair (aIndexType, aIndex) of NewL() function selects the source items.
	 * A pair (aDestinationIndexType, aDestinationIndex) selects the destination.
	 */
	virtual TInt CopyAllEapSettings(
		const TIndexType aDestinationIndexType,
		const TInt aDestinationIndex) = 0;

private:

	/// ECom uses this key to keep track of DLL usage.
	TUid iDtor_ID_Key;

};

#include "EapGeneralSettings.inl"

#endif // _EAP_GENERAL_SETTINGS_H_

// End of file
