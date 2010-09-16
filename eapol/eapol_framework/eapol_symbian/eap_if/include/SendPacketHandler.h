/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* %version: 5 %
*/

#ifndef SENDPACKETHANDLER_H_
#define SENDPACKETHANDLER_H_

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_SENDPACKETHANDLER_H)
	#define EAP_CLASS_VISIBILITY_SENDPACKETHANDLER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_SENDPACKETHANDLER_H 
	#define EAP_C_FUNC_VISIBILITY_SENDPACKETHANDLER_H 
	#define EAP_FUNC_EXPORT_SENDPACKETHANDLER_H 
	#define EAP_C_FUNC_EXPORT_SENDPACKETHANDLER_H 
#elif defined(EAP_EXPORT_SENDPACKETHANDLER_H)
	#define EAP_CLASS_VISIBILITY_SENDPACKETHANDLER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_SENDPACKETHANDLER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_SENDPACKETHANDLER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_SENDPACKETHANDLER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_SENDPACKETHANDLER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_SENDPACKETHANDLER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_SENDPACKETHANDLER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_SENDPACKETHANDLER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_SENDPACKETHANDLER_H 
	#define EAP_C_FUNC_EXPORT_SENDPACKETHANDLER_H 
#endif
// End: added by script change_export_macros.sh.

class EapMessageBuffer;

class EAP_CLASS_VISIBILITY_SENDPACKETHANDLER_H MSendPacketHandler
    {
public:

    virtual eap_status_e send_data(const TDesC8& message) = 0;

    };


#endif /* SENDPACKETHANDLER_H_ */

