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
* %version: 5 %
*/

#ifndef _EAP_TYPE_DEFINITIONS_H_
#define _EAP_TYPE_DEFINITIONS_H_

// INCLUDES
#include <e32base.h>
#include <ecom/ecom.h> 

#include <EapExpandedType.h>

// The UID for EAP plugin interface. ECom uses this.
const TUid KEapTypeInterfaceUid = {0x101f8e4a};

/// Possible services.
enum TIndexType
{
	EDialoutISP,
	EDialinISP,
	EOutgoingGPRS,
	ELan,
	EVpn
};

struct SIapInfo
{
	TIndexType indexType;
	TInt index;
	TEapExpandedType aEapType;
}; 


#endif // _EAP_TYPE_DEFINITIONS_H_

// End of file
