/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 5 %
*/

#ifndef SENDPACKETHANDLER_H_
#define SENDPACKETHANDLER_H_

class EapMessageBuffer;

class EAP_EXPORT MSendPacketHandler
    {
public:

    virtual eap_status_e send_data(const TDesC8& message) = 0;

    };


#endif /* SENDPACKETHANDLER_H_ */

