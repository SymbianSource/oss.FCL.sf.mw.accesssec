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
* Description: CWEPSecuritySettingsImpl inline functions
*
*/



#ifndef WEPSECURITYSETTINGSIMPL_INL
#define WEPSECURITYSETTINGSIMPL_INL


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::KeyInUse
// ---------------------------------------------------------
//
inline CWEPSecuritySettings::TWEPKeyInUse 
                                     CWEPSecuritySettingsImpl::KeyInUse() const
    { 
    return iKeyInUse; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::Authentication
// ---------------------------------------------------------
//
inline CWEPSecuritySettings::TWEPAuthentication 
                               CWEPSecuritySettingsImpl::Authentication() const
    { 
    return iAuthentication; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::KeyLength
// ---------------------------------------------------------
//
inline CWEPSecuritySettings::TWEPKeyLength 
               CWEPSecuritySettingsImpl::KeyLength( const TInt aElement ) const
    { 
    return iKeyLength[aElement]; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::KeyFormat
// ---------------------------------------------------------
//
inline CWEPSecuritySettings::TWEPKeyFormat 
               CWEPSecuritySettingsImpl::KeyFormat( const TInt aElement ) const
    { 
    return iKeyFormat[aElement]; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::KeyData
// ---------------------------------------------------------
//
inline TDes8* CWEPSecuritySettingsImpl::KeyData( const TInt aElement )
    { 
    return &iKeyData[aElement]; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SetKeyInUse
// ---------------------------------------------------------
//
inline void CWEPSecuritySettingsImpl::SetKeyInUse( 
                           const CWEPSecuritySettings::TWEPKeyInUse aKeyInUse )
    { 
    iKeyInUse = aKeyInUse; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SetAuthentication
// ---------------------------------------------------------
//
inline void CWEPSecuritySettingsImpl::SetAuthentication( 
               const CWEPSecuritySettings::TWEPAuthentication aAuthentication )
    { 
    iAuthentication = aAuthentication; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SetKeyLength
// ---------------------------------------------------------
//
inline void CWEPSecuritySettingsImpl::SetKeyLength( const TInt aElement, 
                         const CWEPSecuritySettings::TWEPKeyLength aKeyLength )
    { 
    iKeyLength[aElement] = aKeyLength; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SetKeyFormat
// ---------------------------------------------------------
//
inline void CWEPSecuritySettingsImpl::SetKeyFormat( const TInt aElement, 
                         const CWEPSecuritySettings::TWEPKeyFormat aKeyFormat )
    { 
    iKeyFormat[aElement] = aKeyFormat; 
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::SetKeyData
// ---------------------------------------------------------
//
inline void CWEPSecuritySettingsImpl::SetKeyData( const TInt aElement, 
                                                  const TDesC8& aKeyData )
    {
    iKeyData[aElement] = aKeyData;
    }


// ---------------------------------------------------------
// CWEPSecuritySettingsImpl::WEP256Enabled
// ---------------------------------------------------------
//
inline TBool CWEPSecuritySettingsImpl::WEP256Enabled() const
    {
    // WEP256 is deprecated.
    return EFalse;
    }


#endif 

// End of File
