/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  EAP-FAST PAC-store IF.
*
*/

/*
* %version: 9 %
*/

#ifndef _EAPFASTPACSTORE_H_
#define _EAPFASTPACSTORE_H_

// INCLUDES
#include <e32base.h>
#include <ecom/ecom.h> 


class CEapFastPacStore
: public CBase
{

public:

    /**
    * Factory function that loads the CEapFastPacStore implementation DLL (plug-in).
    */
    static CEapFastPacStore * NewL();

	virtual void OpenPacStoreL() = 0;
    
    // this may not be needed at all
    virtual void CreateDeviceSeedL() = 0;

    virtual TBool IsMasterKeyPresentL() = 0;

    virtual TBool IsMasterKeyAndPasswordMatchingL(
		const TDesC8 & aPassword8) = 0;

    virtual TInt CreateAndSaveMasterKeyL(
		const TDesC8 & aPassword8) = 0;

    virtual TInt ComparePacStorePasswordL(
		TDes8 & aPassword8) = 0;

    virtual TBool IsPacStorePasswordPresentL() = 0;

    virtual TInt SetPacStorePasswordL(
		const TDesC8 & aPassword8) = 0;

    virtual TInt DestroyPacStore() = 0;

private:

	/// ECom uses this key to keep track of DLL usage.
	TUid iDtor_ID_Key;

};

#include "EapFastPacStore.inl"


#endif //_EAPFASTPACSTORE_H_
