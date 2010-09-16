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
* %version: 5.1.4 %
*/

#ifndef _EAPTYPEINFO_H_
#define _EAPTYPEINFO_H_

// INCLUDES
#include <e32base.h>

// LOCAL DATA
// This is the maximum length of the information strings.
const TUint KMaxInfoStringLength = 32;

// CLASS DECLARATION
/**
* Class for storing and transferring the EAP type informational parameters. 
*/
NONSHARABLE_CLASS(CEapTypeInfo) : public CBase
{
public:

	/**
	* Empty constructor
	*/ 
	CEapTypeInfo();
	/**
	* Constructor that takes the info as arguments.
	*/ 	
	CEapTypeInfo(
		const TDesC& aReleaseDate, 
		const TDesC& aVersion,
		const TDesC& aManufacturer);
	/**
	* Empty destructor.
	*/ 	
	virtual ~CEapTypeInfo();
	/**
	* Function for setting the info parameters
	*/
	void Set(
		const TDesC& aReleaseDate, 
		const TDesC& aVersion,
		const TDesC& aManufacturer);
	/**
	* Reads release date
	*/
	virtual const TDesC& ReleaseDate() const;

	/**
	* Reads version
	*/
	virtual const TDesC& Version() const;

	/**
	* Reads manufacturer
	*/
	virtual const TDesC& Manufacturer() const;

private:
	TBuf<KMaxInfoStringLength> iReleaseDate; 
	TBufC<KMaxInfoStringLength> iVersion;
	TBufC<KMaxInfoStringLength> iManufacturer;
};

#endif // _EAPTYPEINFO_H_

// End of file
