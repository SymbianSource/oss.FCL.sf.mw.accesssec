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
* Description:  ECom interface definition for WLAN EAPOL interface API.
*
*/

/*
* %version: 5 %
*/

#ifndef EAP_SEND_INTERFACE_H
#define EAP_SEND_INTERFACE_H

// INCLUDES
#include <e32std.h>


/**
 * @brief ECom interface definition for WLAN EAPOL inteface API.
 *
 * This class defines the method used for sending data from EAPOL to WLAN Engine.
 *
 * @since S60 v3.2
 */
class MEapSendInterface
    {

public:

    /**
     * Callback interface to partner.
     *
     * @since S60 v3.2
     * @param aData Pointer to the data to be sent.
     * @param aLength Length of the data to be sent.
     * @return Return value is specified in interface specification.
     */
    virtual TInt SendData(
        const void * const aData, 
        const TInt aLength ) = 0;

    };


#endif // EAP_SEND_INTERFACE_H
