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

#ifndef _CERTIFICATESELECTIONINFO_H_
#define _CERTIFICATESELECTIONINFO_H_

#include "EapTlsPeapUtils.h"
#include "EapTraceSymbian.h"

const TUint KIdentityFieldLength = 64;

class TCertificateSelectionInfo
{

public:

	TCertificateSelectionInfo()
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("TCertificateSelectionInfo::TCertificateSelectionInfo()\n")));
		EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: TCertificateSelectionInfo::TCertificateSelectionInfo()\n"));
	}

	virtual ~TCertificateSelectionInfo()
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("TCertificateSelectionInfo::~TCertificateSelectionInfo()\n")));
		EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: TCertificateSelectionInfo::~TCertificateSelectionInfo()\n"));

		EAP_TRACE_DEBUG_SYMBIAN((_L("TCertificateSelectionInfo::~TCertificateSelectionInfo(): calls iCertificates.ResetAndDestroy()")));
		iCertificates.ResetAndDestroy(); // ResetAndDestroy() function must be called because the objects represented by the array need to be deleted before the array object is destroyed.

		EAP_TRACE_DEBUG_SYMBIAN((_L("TCertificateSelectionInfo::~TCertificateSelectionInfo(): calls iCertificates.Close()")));
		iCertificates.Close(); // The Close() function must be called before RPointerArray object is destroyed.
	}

	RPointerArray<EapCertificateEntry> iCertificates;
};

class TIdentityInfo
{
public:

	TIdentityInfo()
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("TIdentityInfo::TIdentityInfo()\n")));
		EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: TIdentityInfo::TIdentityInfo()\n"));
	}

	virtual ~TIdentityInfo()
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("TIdentityInfo::~TIdentityInfo()\n")));
		EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: TIdentityInfo::~TIdentityInfo()\n"));
	}

	TBool iUseManualUsername;
	TBuf<KIdentityFieldLength> iUsername;
	TBuf<KIdentityFieldLength> iRealm;	
};

#endif // _CERTIFICATESELECTIONINFO_H_
