/*
 * Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
 * All rights reserved.
 * This component and the accompanying materials are made available
 * under the terms of "Eclipse Public License v1.0"
 * which accompanies this distribution, and is available
 * at the URL "http://www.eclipse.org/legal/epl-v10.html".
 *
 * Initial Contributors:
 * Nokia Corporation - initial contribution.
 *
 * Contributors:
 *
 * Description:  EAP-FAST PAC-store IF inlines
 *
 */

/*
 * %version: 6 %
 */

// SYSTEM INCLUDES
#include <EapTraceSymbian.h>

inline CEapFastPacStore* CEapFastPacStore::NewL()
{
    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapFastPacStore::NewL(): start")));

    // This call finds and loads the correct DLL and after that calls the
    // entry function in the interface implementation in the DLL.
    TAny* ptr = 0;

    const TUid KimplementationUid = { 0x2002BC93 };

    TRAPD( err, ptr = REComSession::CreateImplementationL(
            KimplementationUid,
            _FOFF(CEapFastPacStore, iDtor_ID_Key)));

    EAP_TRACE_DEBUG_SYMBIAN((_L("CEapFastPacStore::NewL(): CreateImplementationL(Uid=0x%08x), err=%d, returns ptr=0x%08x\n"),
        KimplementationUid.iUid,
        err,
        ptr));


    User::LeaveIfError(err);

    return reinterpret_cast<CEapFastPacStore *>(ptr);
}

// end
