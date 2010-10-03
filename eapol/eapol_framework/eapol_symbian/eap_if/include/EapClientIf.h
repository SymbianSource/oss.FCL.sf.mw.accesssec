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
* %version: 6 %
*/

#ifndef EAPCLIENTIF_H_
#define EAPCLIENTIF_H_

#include <e32base.h>
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPCLIENTIF_H)
	#define EAP_CLASS_VISIBILITY_EAPCLIENTIF_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPCLIENTIF_H 
	#define EAP_C_FUNC_VISIBILITY_EAPCLIENTIF_H 
	#define EAP_FUNC_EXPORT_EAPCLIENTIF_H 
	#define EAP_C_FUNC_EXPORT_EAPCLIENTIF_H 
#elif defined(EAP_EXPORT_EAPCLIENTIF_H)
	#define EAP_CLASS_VISIBILITY_EAPCLIENTIF_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPCLIENTIF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCLIENTIF_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPCLIENTIF_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPCLIENTIF_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPCLIENTIF_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPCLIENTIF_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCLIENTIF_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPCLIENTIF_H 
	#define EAP_C_FUNC_EXPORT_EAPCLIENTIF_H 
#endif
// End: added by script change_export_macros.sh.
#include "EapServerClientDef.h"

class EAP_CLASS_VISIBILITY_EAPCLIENTIF_H EapClientIf
{
public:

    EAP_FUNC_VISIBILITY_EAPCLIENTIF_H EapClientIf();

    EAP_FUNC_VISIBILITY_EAPCLIENTIF_H virtual ~EapClientIf();

protected:

    EAP_FUNC_VISIBILITY_EAPCLIENTIF_H static TInt GetServerNameAndExe(TBuf<KMaxServerExe> * const ServerName, TBuf<KMaxServerExe> * const ServerExe);

};


#endif /* EAPCLIENTIF_H_ */
