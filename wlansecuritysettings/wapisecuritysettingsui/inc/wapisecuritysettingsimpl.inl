/*
* ==============================================================================
*  Name        : wapisecuritysettingsimpl.inl
*  Part of     : WAPI Security Settings UI
*
*  Description : CWAPISecuritySettingsImpl inline functions
*  Version     : %version:  5 %
*
*  Copyright (c) 2008 Nokia Corporation.
*  This material, including documentation and any related 
*  computer programs, is protected by copyright controlled by 
*  Nokia Corporation. All rights are reserved. Copying, 
*  including reproducing, storing, adapting or translating, any 
*  or all of this material requires the prior written consent of 
*  Nokia Corporation. This material also contains confidential 
*  information which may not be disclosed to others without the 
*  prior written consent of Nokia Corporation.
* ==============================================================================
*/


#ifndef WAPISECURITYSETTINGSIMPL_INL
#define WAPISECURITYSETTINGSIMPL_INL

// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::GetUserCertInUse
// ---------------------------------------------------------
//
inline void CWAPISecuritySettingsImpl::GetUserCertInUse(
                                                TInt& aUserCertInUse )
    {
    aUserCertInUse = iUserCertInUse;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::GetCACertInUse
// ---------------------------------------------------------
//
inline void CWAPISecuritySettingsImpl::GetCACertInUse(
                                                TInt& aCACertInUse )
    { 
    aCACertInUse = iCACertInUse;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::SetUserCertInUse
// ---------------------------------------------------------
//
inline void CWAPISecuritySettingsImpl::SetUserCertInUse( 
                                                const TInt aSelectedCert )
    {
    iUserCertInUse = aSelectedCert;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::SetCACertInUse
// ---------------------------------------------------------
//
inline void CWAPISecuritySettingsImpl::SetCACertInUse(
                                                const TInt aSelectedCert )
    {
    iCACertInUse = aSelectedCert;
    }


// ---------------------------------------------------------
// CWAPISecuritySettingsImpl::GetCertificateLabels
// ---------------------------------------------------------
//
inline void CWAPISecuritySettingsImpl::GetCertificateLabels( 
                        RArray<TBuf<KMaxLabelLength> >*& aUserCertificates, 
                        RArray<TBuf<KMaxLabelLength> >*& aCACertificates )
    {
    aUserCertificates = iUserCertificates;
    aCACertificates = iCACertificates;
    }

#endif 

// End of File
