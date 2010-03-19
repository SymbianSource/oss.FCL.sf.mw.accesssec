/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_symbian/wlanwapiif/inc/wlan_wapi_if_implementation.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 5 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/

#ifndef _WLAN_WAPI_INTERFACE_IMPLEMENTATION_H_
#define _WLAN_WAPI_INTERFACE_IMPLEMENTATION_H_

// INCLUDES
#include <e32std.h>
#include <wlaneapolclient.h>

#include "abs_wapi_message_wlan_authentication.h"

/**
 * Implementation for MWlanEapolInterface interface.
 *
 * @lib wlanwapiif.dll
 */
class CWlanWAPIInterfaceImplementation
: public CWlanEapolClient
, public abs_wapi_message_wlan_authentication_c
{

public:

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// Functions from CWlanEapolClient.

	/**
	 * Static constructor.
	 * @param aPartner Pointer to callback instance.
	 * @return Pointer to the constructed instance.
	 */
	static CWlanWAPIInterfaceImplementation* NewL( MWlanEapolCallbackInterface * aPartner );

	/**
	 * Destructor.
	 */
	virtual ~CWlanWAPIInterfaceImplementation();

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
    CWlanWAPIInterfaceImplementation();

    /**
     * Symbian 2nd phase constructor.
     */
    void ConstructL(MWlanEapolCallbackInterface * aPartner);

	/**
	 * The get_is_valid() function returns the status of the CWlanWAPIInterfaceImplementation object.
	 * @return True indicates the object is initialized.
	 */
	bool get_is_valid();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	abs_eap_am_tools_c * m_am_tools;

	MWlanEapolCallbackInterface * m_partner;

	wapi_message_wlan_authentication_c * m_wauth;

	bool m_is_valid;

};


#endif // _WLAN_EAPOL_INTERFACE_IMPLEMENTATION_H_

// End of file.
