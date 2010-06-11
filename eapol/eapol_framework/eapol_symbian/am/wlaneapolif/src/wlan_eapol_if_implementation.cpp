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

// INCLUDES
#include <e32std.h>
#include <implementationproxy.h>

#include "abs_eap_am_tools.h"

#include "eapol_message_wlan_authentication.h"
#include "wlan_eapol_if_implementation.h"
#include "wlan_eap_if_send_status.h"

//-----------------------------------------------------------------------------------------

/**
 * Pairs ECom implementation UIDs with a pointer to the instantiation 
 * method for that implementation. Required for all ECom implementation
 * collections.
 */
const TImplementationProxy ImplementationTable[] =
{
    {{ KCWlanEapolClientUid }, reinterpret_cast<TProxyNewLPtr>(CWlanEapolInterfaceImplementation::NewL)}
};

//-----------------------------------------------------------------------------------------

/**
 * Static constructor.
 * @param aPartner Pointer to callback instance.
 * @return Pointer to the constructed instance.
 */
CWlanEapolInterfaceImplementation* CWlanEapolInterfaceImplementation::NewL(MWlanEapolCallbackInterface * aPartner)
{
	CWlanEapolInterfaceImplementation* self = new (ELeave) CWlanEapolInterfaceImplementation;

	CleanupStack::PushL(self);

	self->ConstructL(aPartner);

	if (self->get_is_valid() != true)
	{
		User::Leave(KErrGeneral);
	}

	CleanupStack::Pop(self);

	return self;
}

//-----------------------------------------------------------------------------------------

/**
 * C++ default constructor.
 */
CWlanEapolInterfaceImplementation::CWlanEapolInterfaceImplementation()
: m_am_tools(0)
, m_partner(0)
, m_wauth(0)
, m_is_valid(true)
{
}

//-----------------------------------------------------------------------------------------

/**
 * Destructor.
 */
CWlanEapolInterfaceImplementation::~CWlanEapolInterfaceImplementation()
{
	m_partner = 0;

	delete m_wauth;
	m_wauth = 0;
  m_am_tools->am_cancel_all_timers();
	abs_eap_am_tools_c::delete_abs_eap_am_tools_c(m_am_tools);
	m_am_tools = 0;

}

//-----------------------------------------------------------------------------------------

/**
 * Configure plugin implementation.
 *
 * @since S60 v3.2
 * @param aHeaderOffset Offset of EAP-header in packet_send.
 * @param aMTU Maximum transfer unit (MTU).
 * @param aTrailerLength Length of trailer needed by lower levels..
 * @return Return value is specified in interface specification.
 */
TInt CWlanEapolInterfaceImplementation::Configure(
	const TInt aHeaderOffset,
	const TInt aMTU,
	const TInt aTrailerLength)
{
	m_am_tools = abs_eap_am_tools_c::new_abs_eap_am_tools_c();

	if (m_am_tools == 0)
	{
		return wlan_eap_if_send_status_conversion_c::convert(eap_status_allocation_error);
	}

	// eapol_message_wlan_authentication_c object uses the tools object.
	m_wauth = new eapol_message_wlan_authentication_c(
		m_am_tools,
		this);

	if (m_wauth != 0
		&& m_wauth->get_is_valid() == true)
	{
		eap_status_e status = m_wauth->configure(
			aHeaderOffset,
			aMTU,
			aTrailerLength);
		if (status != eap_status_ok)
		{
			return wlan_eap_if_send_status_conversion_c::convert(
				EAP_STATUS_RETURN(m_am_tools, status));
		}
	}
	else
	{
		return wlan_eap_if_send_status_conversion_c::convert(
			EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error));
	}

	return wlan_eap_if_send_status_ok;
}

//-----------------------------------------------------------------------------------------

/**
 * Shutdown plugin implementation.
 *
 * @since S60 v3.2
 * @return Return value is specified in interface specification.
 */        
TInt CWlanEapolInterfaceImplementation::Shutdown()
{
	eap_status_e status = m_wauth->shutdown();

	return wlan_eap_if_send_status_conversion_c::convert(
			EAP_STATUS_RETURN(m_am_tools, status));
}

//-----------------------------------------------------------------------------------------

/**
 * Send data to EAPOL.
 *
 * @since S60 v3.2
 * @param aData Pointer to the data to be sent.
 * @param aLength Length of the data to be sent.
 * @return Return value is specified in interface specification.
 */
TInt CWlanEapolInterfaceImplementation::ProcessData(
	const void * const aData, 
	const TInt aLength )
{
	return m_wauth->process_data(aData, aLength);
}

//-----------------------------------------------------------------------------------------

/**
 * Symbian 2nd phase constructor.
 */
void CWlanEapolInterfaceImplementation::ConstructL(MWlanEapolCallbackInterface * aPartner)
{
	m_partner = aPartner;
}

//-----------------------------------------------------------------------------------------

bool CWlanEapolInterfaceImplementation::get_is_valid()
{
	return m_is_valid;
}

//-----------------------------------------------------------------------------------------

/// Function sends the data message to lower layer.
/// Data is formatted to Attribute-Value Pairs.
/// Look at eap_tlv_header_c and eap_tlv_message_data_c.
wlan_eap_if_send_status_e CWlanEapolInterfaceImplementation::send_data(const void * const data, const u32_t length)
{
	return static_cast<wlan_eap_if_send_status_e>(m_partner->SendData(
        data, 
        length));
}

//-----------------------------------------------------------------------------------------

// ======== GLOBAL FUNCTIONS ========

// ---------------------------------------------------------
// Returns an instance of the proxy table.
// Returns: KErrNone
// ---------------------------------------------------------
//
EXPORT_C const TImplementationProxy* ImplementationGroupProxy( TInt& aTableCount )
    {
    aTableCount = sizeof( ImplementationTable) / sizeof( TImplementationProxy );
    return ImplementationTable;
    }

//-----------------------------------------------------------------------------------------

// End of file.

