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
* %version: 8.1.2 %
*/

#ifndef _SCERTENTRY_H_
#define _SCERTENTRY_H_


#include <unifiedcertstore.h>
#include <cctcertinfo.h>

/* This is the maximum length of a certificate primary/secondary name we are interested in. */
const TUint32 KMaxNameLength = 64;

struct SCertEntry
{
	TCertLabel iLabel;	// This holds only the certificate label.
	TKeyIdentifier iSubjectKeyId;
	TBuf<KMaxNameLength> iPrimaryName; // Primary name of the certificate if any.
	TBuf<KMaxNameLength> iSecondaryName; // Secondary name of the certificate if any.
};

#endif // _SCERTENTRY_H_

// End of file


