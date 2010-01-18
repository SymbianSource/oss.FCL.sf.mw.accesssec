/*
* Copyright (c) 2001-2009 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: Stub implementation of class CWEPSecuritySettings for 
*              non-WLAN products to support linking 
*
*/

/*
* %version: 2 %
*/

// INCLUDE FILES

#include <WEPSecuritySettingsUi.h>



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWEPSecuritySettings::NewL
// ---------------------------------------------------------
//
EXPORT_C CWEPSecuritySettings* CWEPSecuritySettings::NewL()
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::~CWEPSecuritySettings
// ---------------------------------------------------------
//
EXPORT_C CWEPSecuritySettings::~CWEPSecuritySettings()
    {
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::LoadL( TUint32 /* aIapId */, 
                                           CCommsDatabase& /* aCommsDb */ )
    {
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SaveL( TUint32 /* aIapId */, 
                                           CCommsDatabase& /* aCommsDb */ ) const
    {
    }
    

// ---------------------------------------------------------
// CWEPSecuritySettings::EditL
// ---------------------------------------------------------
//
EXPORT_C TInt CWEPSecuritySettings::EditL( CWEPSecuritySettingsUi& /* aUi */,
                                           const TDesC& /* aTitle */ )
    {
    return KErrNotSupported;
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::IsValid
// ---------------------------------------------------------
//
EXPORT_C TBool CWEPSecuritySettings::IsValid() const
    {
    return EFalse;
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SetKeyDataL
// ---------------------------------------------------------
//
EXPORT_C TInt CWEPSecuritySettings::SetKeyDataL( const TInt /* aElement */,
                                                 const TDesC& /* aKeyData */,
                                                 const TBool /* aHex */ )
    {
    return KErrNotSupported;
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::LoadL( TUint32 /* aIapId */, 
                                           CMDBSession& /* aSession */ )
    {
    }
    

// ---------------------------------------------------------
// CWEPSecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SaveL( TUint32 /* aIapId */, 
                                           CMDBSession& /* aSession */ ) const
    {
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SetKeyInUse
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SetKeyInUse( 
                                      CWEPSecuritySettings::TWEPKeyInUse /* aKey */ )
    {
    }


// ---------------------------------------------------------
// CWEPSecuritySettings::SetAuthentication
// ---------------------------------------------------------
//
EXPORT_C void CWEPSecuritySettings::SetAuthentication( 
                     CWEPSecuritySettings::TWEPAuthentication /* aAuthentication */ )
    {
    }

// End of File
