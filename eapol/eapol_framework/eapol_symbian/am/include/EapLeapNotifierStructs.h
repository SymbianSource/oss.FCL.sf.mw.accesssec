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
* %version: %
*/

#ifndef EAPLEAPNOTIFIERSTRUCTS_H
#define EAPLEAPNOTIFIERSTRUCTS_H

struct TEapLeapUsernamePasswordInfo
{
	TBool iPasswordPromptEnabled;
	TBool iIsIdentityQuery;
	TBuf16<256> iUsername;
	TBuf16<256> iPassword;
};

#endif // EAPLEAPNOTIFIERSTRUCTS_H

// End of File
