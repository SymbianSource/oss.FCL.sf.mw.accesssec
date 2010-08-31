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
	#define EAP_FILE_NUMBER_ENUM 435 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <EapTlsPeapUiTlsPeapData.h>


CEapTlsPeapUiTlsPeapData::CEapTlsPeapUiTlsPeapData()
: iAllowVersion0(EFalse),
iAllowVersion1(EFalse),
iAllowVersion2(EFalse),
iPapPasswordPrompt( ETrue ),
iPasswordPrompt(ETrue)
{
}


CEapTlsPeapUiTlsPeapData::~CEapTlsPeapUiTlsPeapData()
{
}


TDes& CEapTlsPeapUiTlsPeapData::GetManualUsername()
{
    return iManualUsername;
}

TBool * CEapTlsPeapUiTlsPeapData::GetUseManualUsername()
{
    return &iUseManualUsername;
}

TDes& CEapTlsPeapUiTlsPeapData::GetManualRealm()
{
    return iManualRealm;
}


TBool * CEapTlsPeapUiTlsPeapData::GetUseManualRealm()
{
    return &iUseManualRealm;
}

TBool * CEapTlsPeapUiTlsPeapData::GetAllowVersion0()
{
	return &iAllowVersion0;
}

TBool * CEapTlsPeapUiTlsPeapData::GetAllowVersion1()
{
	return &iAllowVersion1;
}

TBool * CEapTlsPeapUiTlsPeapData::GetAllowVersion2()
{
	return &iAllowVersion2;
}

TBool * CEapTlsPeapUiTlsPeapData::GetTlsPrivacy()
{
	return &iTlsPrivacy;
}
	
TBool * CEapTlsPeapUiTlsPeapData::GetAuthProvModeAllowed()
{
	return &iAuthProvModeAllowed;
}
	
TBool * CEapTlsPeapUiTlsPeapData::GetUnauthProvModeAllowed()
{
	return &iUnauthProvModeAllowed;
}

TDes& CEapTlsPeapUiTlsPeapData::GetPacStorePassword()
{
	return iPacStorePassword;
}

TBool* CEapTlsPeapUiTlsPeapData::GetUsePacStorePasswordPrompt()
{
	return &iPasswordPrompt;
}


// ---------------------------------------------------------
// CEapTlsPeapUiTlsPeapData::GetPapUserName()
// ---------------------------------------------------------
//    
TDes& CEapTlsPeapUiTlsPeapData::GetPapUserName()
    {
    return iPapUserName;
    }

// ---------------------------------------------------------
// CEapTlsPeapUiTlsPeapData::GetPapPassword()
// ---------------------------------------------------------
//    
TDes& CEapTlsPeapUiTlsPeapData::GetPapPassword()
    {
    return iPapPassword;
    }

// ---------------------------------------------------------
// CEapTlsPeapUiTlsPeapData::GetPapPasswordPrompt()
// ---------------------------------------------------------
//    
TBool* CEapTlsPeapUiTlsPeapData::GetPapPasswordPrompt()
    {
    return &iPapPasswordPrompt;
    }

// End of file
