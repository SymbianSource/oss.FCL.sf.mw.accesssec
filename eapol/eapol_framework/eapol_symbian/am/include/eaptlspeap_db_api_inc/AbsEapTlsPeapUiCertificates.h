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

#ifndef _ABSEAPTLSPEAPUICERTIFICATES_H_
#define _ABSEAPTLSPEAPUICERTIFICATES_H_

// INCLUDES

// CLASS DECLARATION
/**
* Class for 
*/
class MEapTlsPeapUiCertificates
{
public:
	/**
	* 
	*/
	virtual void CompleteReadCertificates(const TInt aResult) = 0;	
};

#endif // _ABSEAPTLSPEAPUICERTIFICATES_H_

// End of file
