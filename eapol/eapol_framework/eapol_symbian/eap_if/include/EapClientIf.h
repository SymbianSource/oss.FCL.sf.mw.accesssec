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

#ifndef EAPCLIENTIF_H_
#define EAPCLIENTIF_H_

#include <e32base.h>
#include "EapServerClientDef.h"

class EapClientIf
{
public:

    IMPORT_C EapClientIf();

    IMPORT_C virtual ~EapClientIf();

protected:
    IMPORT_C static TInt GetServerNameAndExe(TBuf<KMaxServerExe> * const ServerName, TBuf<KMaxServerExe> * const ServerExe);
};


#endif /* EAPCLIENTIF_H_ */
