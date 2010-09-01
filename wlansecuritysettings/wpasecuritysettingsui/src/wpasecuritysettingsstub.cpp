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
* Description: Stub implementation of class CWPASecuritySettings for 
*              non-WLAN products to support linking 
*
*/

/*
* %version: 2 %
*/

// INCLUDE FILES
#include <WPASecuritySettingsUI.h>



// ================= MEMBER FUNCTIONS =======================

// ---------------------------------------------------------
// CWPASecuritySettings::NewL
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettings* CWPASecuritySettings::NewL( 
                                                TSecurityMode /*aSecurityMode*/ )
    {
    User::Leave(KErrNotSupported);
    return NULL;
    }


// ---------------------------------------------------------
// CWPASecuritySettings::~CWPASecuritySettings
// ---------------------------------------------------------
//
EXPORT_C CWPASecuritySettings::~CWPASecuritySettings()
    {
    }


// ---------------------------------------------------------
// CWPASecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::LoadL( TUint32 /*aIapId*/, 
                                           CCommsDatabase& /*aCommsDb*/ )
    {
    }


// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::SaveL( TUint32 /*aIapId*/, 
                                           CCommsDatabase& /*aCommsDb*/, 
                                           TTypeOfSaving /*aTypeOfSaving*/, 
                                           TUint32 /*aOldIapId*/ ) const
    {
    }
    

// ---------------------------------------------------------
// CWPASecuritySettings::EditL
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::EditL( CWPASecuritySettingsUi& /*aUi*/,
                                           const TDesC& /*aTitle*/ )
    {
    return KErrNotSupported;
    }


// ---------------------------------------------------------
// CWPASecuritySettings::DeleteL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::DeleteL( TUint32 /*aIapId*/ ) const
    {
    }


// ---------------------------------------------------------
// CWPASecuritySettings::IsValid
// ---------------------------------------------------------
//
EXPORT_C TBool CWPASecuritySettings::IsValid() const
    {
    return EFalse;
    }


// ---------------------------------------------------------
// CWPASecuritySettings::SetWPAPreSharedKey
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::SetWPAPreSharedKey( 
                                                const TDesC& /*aPreSharedKey*/ )
    {
    return KErrNotSupported;
    }


// ---------------------------------------------------------
// CWPASecuritySettings::LoadL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::LoadL( TUint32 /*aIapId*/, 
                                           CMDBSession& /*aSession*/ )
    {
    }
    
    
// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C void CWPASecuritySettings::SaveL( TUint32 /*aIapId*/,
                                           CMDBSession& /*aSession*/,
                                           TTypeOfSaving /*aTypeOfSaving*/,
                                           TUint32 /*aOldIapId*/ ) const
    {
    }


// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::SetWPAEnabledEAPPlugin( 
                                            const TDesC8& /*aEnabledPluginList*/ )
    {
    return KErrNotSupported;
    }

// ---------------------------------------------------------
// CWPASecuritySettings::SaveL
// ---------------------------------------------------------
//
EXPORT_C TInt CWPASecuritySettings::SetWPADisabledEAPPlugin( 
                                            const TDesC8& /*aDisabledPluginList*/ )
    {
    return KErrNotSupported;
    }

// End of File
