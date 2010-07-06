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
* %version: 22 %
*/

#include "EapTraceSymbian.h"


// Used By UI
inline CEapType* CEapType::NewL(const TIndexType aIndexType, const TInt aIndex, const TEapExpandedType aEapType)
{
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapType::NewL(EapGeneric): start")));

    // The arguments are stored to a iapInfo struct.
    SIapInfo iapInfo;
    iapInfo.indexType = aIndexType;
    iapInfo.index = aIndex;
    iapInfo.aEapType = aEapType;

    // This call finds and loads the correct DLL and after that calls the
    // entry function in the interface implementation in the DLL.
    TAny* ptr = 0;

    const TUid KimplementationUid = { 0x20026FD2 };

    TRAPD( err, ptr = REComSession::CreateImplementationL(
            KimplementationUid,
            _FOFF(CEapType, iDtor_ID_Key), 
            &iapInfo));

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapType::NewL(EapGeneric): CreateImplementationL(Uid=0x%08x), err=%d, returns ptr=0x%08x\n"),
		KimplementationUid.iUid,
        err,
        ptr));

    User::LeaveIfError(err);

    return (CEapType *) ptr;
}

inline CEapType::~CEapType()
{
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapType::~CEapType(): this=0x%08x"),
		this));

	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: CEapType::~CEapType()"));

	// Unload DLL
    REComSession::DestroyedImplementation(iDtor_ID_Key);
}

// End of file
