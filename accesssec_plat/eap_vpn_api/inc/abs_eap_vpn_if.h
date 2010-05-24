/*
* Copyright (c) 2005 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: EAP and WLAN authentication protocols.
*
*/

/*
* %version: %
*/

#ifndef __EAPPLUGINCALLBACKINTERFACE_H__
#define __EAPPLUGINCALLBACKINTERFACE_H__

// INCLUDES

// Enums
enum TNotification
{
    ESuccess,
    EFailure,
    ECancelled,
    EFailedCompletely,
    ELogoff,
    ENoResponse
};

/**
 * Class:       MAbsEapVpnInterface
 *
 * Description: This interface defines the callback functions required from the CEaplugin user
 */
class MAbsEapVpnInterface
{
    public:
    /**
	 * Function:    EapOutbound
	 *
	 * Description: Callback function, which returns an outbound EAP message
	 *
     */
     virtual void EapOutboundL(HBufC8* aResponse) = 0;

    /**
	 * Function:    IdentityResponse
	 *
	 * Description: Callback function, which returns identity
	 *
     */
     virtual void EapIdentityResponseL(HBufC8* aIdentity) = 0;

    /**
	 * Function:    EapSharedKey
	 *
	 * Description: Callback function, which returns a shared key established during EAP session
	 *
     */
     virtual void EapSharedKeyL(HBufC8* aSharedKey) = 0;

    /**
	 * Function:    EapIndication
	 *
	 * Description: Callback function, which returns notifications
	 *
     * @param       aNotification numeric notification
     */
     virtual void EapIndication(TNotification aNotification) = 0;
};     
#endif
