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
* %version: %
*/

#ifndef _WLAN_EAPOL_INTERFACE_IMPLEMENTATION_H_
#define _WLAN_EAPOL_INTERFACE_IMPLEMENTATION_H_

// INCLUDES
#include <e32std.h>
#include <wlaneapolclient.h>

#include "abs_eapol_message_wlan_authentication.h"

/**
 * Implementation for MWlanEapolInterface interface.
 *
 * @lib wlaneapolif.dll
 * @since S60 v3.2
 */
class CWlanEapolInterfaceImplementation
: public CWlanEapolClient
, public abs_eapol_message_wlan_authentication_c
{

public:

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from CWlanEapolClient.

	/**
	 * Static constructor.
	 * @param aPartner Pointer to callback instance.
	 * @return Pointer to the constructed instance.
	 */
	static CWlanEapolInterfaceImplementation* NewL( MWlanEapolCallbackInterface * aPartner );

	/**
	 * Destructor.
	 */
	virtual ~CWlanEapolInterfaceImplementation();

	/**
	 * Configure plugin implementation.
	 *
	 * @since S60 v3.2
	 * @param aHeaderOffset Offset of EAP-header in packet_send.
	 * @param aMTU Maximum transfer unit (MTU).
	 * @param aTrailerLength Length of trailer needed by lower levels..
	 * @return Return value is specified in interface specification.
	 */
	virtual TInt Configure(
		const TInt aHeaderOffset,
		const TInt aMTU,
		const TInt aTrailerLength);

	/**
	 * Shutdown plugin implementation.
	 *
	 * @since S60 v3.2
	 * @return Return value is specified in interface specification.
	 */        
	virtual TInt Shutdown();

	/**
	 * Send data to EAPOL.
	 *
	 * @since S60 v3.2
	 * @param aData Pointer to the data to be sent.
	 * @param aLength Length of the data to be sent.
	 * @return Return value is specified in interface specification.
	 */
	virtual TInt ProcessData(
		const void * const aData, 
		const TInt aLength );

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from abs_eapol_message_wlan_authentication_c.

	/// Function sends the data message to lower layer.
	/// Data is formatted to Attribute-Value Pairs.
	/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
	virtual wlan_eap_if_send_status_e send_data(const void * const data, const u32_t length);


private:

    /**
     * C++ default constructor.
     */
    CWlanEapolInterfaceImplementation();

    /**
     * Symbian 2nd phase constructor.
     */
    void ConstructL(MWlanEapolCallbackInterface * aPartner);

	/**
	 * The get_is_valid() function returns the status of the CWlanEapolInterfaceImplementation object.
	 * @return True indicates the object is initialized.
	 */
	bool get_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	abs_eap_am_tools_c * m_am_tools;

	MWlanEapolCallbackInterface * m_partner;

	eapol_message_wlan_authentication_c * m_wauth;

	bool m_is_valid;

};


#endif // _WLAN_EAPOL_INTERFACE_IMPLEMENTATION_H_

// End of file.
