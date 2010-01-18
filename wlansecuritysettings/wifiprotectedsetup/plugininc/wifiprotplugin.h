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
* Description: Declaration of Wi-Fi Protected Setup Notifier Array
*
*/

/*
* %version: tr1cfwln#6 %
*/

#ifndef WIFIPROTPLUGIN_H
#define WIFIPROTPLUGIN_H


// INCLUDES
#if !defined(__EIKNOTAPI_H__)
#include <eiknotapi.h>
#endif

// GLOBAL FUNCTIONS
//
/**
* Array of connection dialog plugins.
* @return A CArrayPtr of MEikSrvNotifierBase2 based classes.
*/
IMPORT_C CArrayPtr<MEikSrvNotifierBase2>* NotifierArray();


// RSC file name.
_LIT( KResourceFileName, "WiFiProtPlugin.rsc" );

    
#endif //WIFIPROTPLUGIN_H

// End of File
