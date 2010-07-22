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
* %version: 7 %
*/

#include "EapTraceSymbian.h"

inline CEapGeneralSettings* CEapGeneralSettings::NewL(
		const TIndexType aIndexType,	
		const TInt aIndex)
{
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapGeneralSettings::NewL(): start")));

    // The arguments are stored to a iapInfo struct.
    SIapInfo iapInfo;
    iapInfo.indexType = aIndexType;
    iapInfo.index = aIndex;
    iapInfo.aEapType = *EapExpandedTypeNone.GetType();

    // This call finds and loads the correct DLL and after that calls the
    // entry function in the interface implementation in the DLL.
    TAny* ptr = 0;

    const TUid KimplementationUid = { 0x20026FD8 };

    TRAPD( err, ptr = REComSession::CreateImplementationL(
            KimplementationUid,
            _FOFF(CEapGeneralSettings, iDtor_ID_Key), 
            &iapInfo));

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapGeneralSettings::NewL(): CreateImplementationL(Uid=0x%08x), err=%d, returns ptr=0x%08x\n"),
		KimplementationUid.iUid,
        err,
        ptr));

    User::LeaveIfError(err);

    return (CEapGeneralSettings *) ptr;
}

inline CEapGeneralSettings::~CEapGeneralSettings()
{
	// Unload DLL
    REComSession::DestroyedImplementation(iDtor_ID_Key);
}

// End of file
