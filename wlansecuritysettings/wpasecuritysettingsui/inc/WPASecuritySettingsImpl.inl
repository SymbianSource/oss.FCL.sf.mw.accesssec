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
* Description: CWPASecuritySettingsImpl inline functions
*
*/



#ifndef WPASECURITYSETTINGSIMPL_INL
#define WPASECURITYSETTINGSIMPL_INL


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SecurityMode
// ---------------------------------------------------------
//
inline TSecurityMode CWPASecuritySettingsImpl::SecurityMode() const
    {
    return iSecurityMode;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::WPAMode
// ---------------------------------------------------------
//
inline TBool CWPASecuritySettingsImpl::WPAMode() const
    { 
    return iWPAMode; 
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::Wpa2Only
// ---------------------------------------------------------
//
inline TBool CWPASecuritySettingsImpl::Wpa2Only() const
    { 
    return iWpa2Only; 
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::WPAPreSharedKey
// ---------------------------------------------------------
//
inline TDes8* CWPASecuritySettingsImpl::WPAPreSharedKey()
    { 
    return &iWPAPreSharedKey; 
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::WPAEAPPlugin
// ---------------------------------------------------------
//
inline TDes* CWPASecuritySettingsImpl::WPAEAPPlugin()
    {
    return &iWPAEAPPlugin;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::WPAEnabledEAPPlugin
// ---------------------------------------------------------
//
inline HBufC8* CWPASecuritySettingsImpl::WPAEnabledEAPPlugin()
    {
    return iWPAEnabledEAPPlugin;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::WPADisabledEAPPlugin
// ---------------------------------------------------------
//
inline HBufC8* CWPASecuritySettingsImpl::WPADisabledEAPPlugin()
    {
    return iWPADisabledEAPPlugin;
    }
        
    
// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SetWPAMode
// ---------------------------------------------------------
//
inline void CWPASecuritySettingsImpl::SetWPAMode( const TBool aWPAMode )
    { 
    iWPAMode = aWPAMode; 
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SetWpa2Only
// ---------------------------------------------------------
//
inline void CWPASecuritySettingsImpl::SetWpa2Only( const TBool aWpa2Only )
    { 
    iWpa2Only = aWpa2Only; 
    }



// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SetWPAPreSharedKey
// ---------------------------------------------------------
//
inline void CWPASecuritySettingsImpl::SetWPAPreSharedKey(
                                              const TDesC8& aWPAPreSharedKey )
    {
    iWPAPreSharedKey = aWPAPreSharedKey;
    }


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SetIapId
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::SetIapId( const TUint32 aIapId )
	{
	iIapId = aIapId;
	}


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::IapId
// ---------------------------------------------------------
//
const TUint32 CWPASecuritySettingsImpl::IapId()
	{
	return iIapId;
	}


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::SetWPAEAPPlugin
// ---------------------------------------------------------
//
void CWPASecuritySettingsImpl::SetWPAEAPPlugin( const TDes& aPluginList )
	{
	iWPAEAPPlugin.Copy( aPluginList );
	}


// ---------------------------------------------------------
// CWPASecuritySettingsImpl::Plugin
// ---------------------------------------------------------
//
CEAPPluginConfigurationIf* CWPASecuritySettingsImpl::Plugin()
	{
	return iPlugin;
	}


#endif 

// End of File
