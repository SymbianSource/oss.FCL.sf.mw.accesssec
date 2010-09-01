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
* %version: 6.1.2 %
*/

#ifndef _CERTIFICATESELECTIONINFO_H_
#define _CERTIFICATESELECTIONINFO_H_

#include "EapTlsPeapUtils.h"

const TUint KIdentityFieldLength = 64;

struct TCertificateSelectionInfo
{
	TInt iCount;
	TFixedArray<SCertEntry, 32> iCertificates;
};

struct TIdentityInfo
{
	TBool iUseManualUsername;
	TBuf<KIdentityFieldLength> iUsername;
	TBuf<KIdentityFieldLength> iRealm;	
};

#endif // _CERTIFICATESELECTIONINFO_H_
