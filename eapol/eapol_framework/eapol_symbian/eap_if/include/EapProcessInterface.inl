/*
* Copyright (c) 2006-2007 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Symbian Foundation License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.symbianfoundation.org/legal/sfl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  Inline functions of CWlanEapolClient class.
*
*/

/*
* %version: %
*/

#include <ecom/ecom.h>
#include "EapTraceSymbian.h"
// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
//

inline CEapProcessInterface* CEapProcessInterface::NewL(
    TInt aUid,
    MEapSendInterface * aPartner)
    {
     
    EAP_TRACE_DEBUG_SYMBIAN(
        (_L("CEapProcessInterface::NewL")));  

    const TUid KTMPUid = { aUid };

    EAP_TRACE_DEBUG_SYMBIAN(
        (_L("CEapProcessInterface::NewL KTMPUid created ")));  

    TAny* aInterface = REComSession::CreateImplementationL(
        KTMPUid,
        _FOFF( CEapProcessInterface, iInstanceIdentifier ),
        aPartner);

    EAP_TRACE_DEBUG_SYMBIAN(
        (_L("CEapProcessInterface::NewL CreateImplementationL done")));  

    return reinterpret_cast<CEapProcessInterface*>( aInterface );
    }

// -----------------------------------------------------------------------------
// -----------------------------------------------------------------------------
//
inline CEapProcessInterface::~CEapProcessInterface()
    {
    REComSession::DestroyedImplementation( iInstanceIdentifier );
    }
