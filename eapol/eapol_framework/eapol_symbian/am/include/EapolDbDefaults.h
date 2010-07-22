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
* %version: 5.1.5 %
*/

#if !defined(_EAPOLDBDEFAULTS_H_)
#define _EAPOLDBDEFAULTS_H_

// LOCAL CONSTANTS

// For EAPOL database.
// Database will be written to private folder of the WLAN-server.
_LIT(KEapolDatabaseName, "eapol.dat");

_LIT(default_EAP_TRACE_output_file_name, "c:\\logs\\eapol\\eap_core.txt");

#if !defined(USE_EAP_FILECONFIG)
	const TInt default_EAPOL_CORE_starts_max_count = 3;		
	const TInt default_EAPOL_CORE_send_start_interval = 2000; // ms
#endif //#if !defined(USE_EAP_FILECONFIG)

#endif // _EAPOLDBDEFAULTS_H_

// End of file
