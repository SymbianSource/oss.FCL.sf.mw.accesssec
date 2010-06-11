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

#ifndef ABSEAPSENDINTERFACE_H_
#define ABSEAPSENDINTERFACE_H_

#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "EapServerClientDef.h"

class EAP_EXPORT AbsEapSendInterface
    {

private:

public:

    virtual ~AbsEapSendInterface()
        {
        }

    /// Function sends the data message to lower layer.
    /// Data is formatted to Attribute-Value Pairs.
    /// Look at eap_tlv_header_c and eap_tlv_message_data_c.
    virtual eap_status_e SendData(const void * const data, const u32_t length, TEapRequests message) = 0;

    };
#endif /* ABSEAPSENDINTERFACE_H_ */
