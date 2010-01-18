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
* %version: 7.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 302 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include <EapMsChapV2UiMsChapV2Data.h>


CEapMsChapV2UiMsChapV2Data::CEapMsChapV2UiMsChapV2Data()
{
}


CEapMsChapV2UiMsChapV2Data::~CEapMsChapV2UiMsChapV2Data()
{
}


TDes& CEapMsChapV2UiMsChapV2Data::GetUsername()
{
    return iUsername;
}


TDes& CEapMsChapV2UiMsChapV2Data::GetPassword()
{
    return iPassword;
}


TBool * CEapMsChapV2UiMsChapV2Data::GetPasswordPrompt()
{
    return &iPasswordPrompt;
}

// End of file
