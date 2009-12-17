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



#ifndef EAPSECURIDNOTIFIERSTRUCTS_H
#define EAPSECURIDNOTIFIERSTRUCTS_H

struct TEapSecurIDStruct
{
	TBool iIsFirstQuery;
	TBuf16<128> iIdentity;
	TBuf16<256> iPasscode;
	TPassword iPincode;
};

#endif // EAPSECURIDNOTIFIERSTRUCTS_H

// End of File
