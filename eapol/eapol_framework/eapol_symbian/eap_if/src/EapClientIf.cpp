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
* Description:  Class stores the EAP-server name.
*
*/

/*
* %version: 6 %
*/

#include "EapClientIf.h"


EXPORT_C EapClientIf::EapClientIf()
{
}

EXPORT_C EapClientIf::~EapClientIf()
{
}

    
EXPORT_C TInt EapClientIf::GetServerNameAndExe(TBuf<KMaxServerExe> * const ServerName, TBuf<KMaxServerExe> * const ServerExe)
{
	_LIT( KEapServerName,"EapAuthServer" );
	_LIT( KEapServerExe, "EapAuthServerExe.exe");

	ServerName->Copy(KEapServerName);
	ServerExe->Copy(KEapServerExe);
	return KErrNone;
}

// end
