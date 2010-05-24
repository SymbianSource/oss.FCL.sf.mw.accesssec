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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 363 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES
#include <EapTypeInfo.h>

// ================= MEMBER FUNCTIONS =======================
CEapTypeInfo::CEapTypeInfo()
{
}

CEapTypeInfo::CEapTypeInfo(const TDesC& aReleaseDate, const TDesC& aVersion,
				 const TDesC& aManufacturer)
: iVersion(aVersion),
iManufacturer(aManufacturer)
{
	// Format the release date according to locale
	TTime date(aReleaseDate);
	_LIT(KDateFormat, "%/0%1%/1%2%/2%3%/3");
	TRAPD(err, date.FormatL(iReleaseDate, KDateFormat));
	if (err != KErrNone)
	{	
		// Something went wrong. Clear release date.
		iReleaseDate.SetLength(0);
	}
}

// ----------------------------------------------------------

CEapTypeInfo::~CEapTypeInfo()
{
}

// ----------------------------------------------------------

void CEapTypeInfo::Set(const TDesC& aReleaseDate, const TDesC& aVersion,
				 const TDesC& aManufacturer)
{
	iReleaseDate = aReleaseDate;
	iVersion = aVersion;
	iManufacturer = aManufacturer;
}

// ----------------------------------------------------------

const TDesC& CEapTypeInfo::ReleaseDate() const
{
	return iReleaseDate;
}

// ----------------------------------------------------------

const TDesC& CEapTypeInfo::Version() const
{
	return iVersion;
}

// ----------------------------------------------------------

const TDesC& CEapTypeInfo::Manufacturer() const
{
	return iManufacturer;
}


// End of file
