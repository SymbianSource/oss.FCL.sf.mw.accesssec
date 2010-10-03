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

#include "eap_am_types.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_DSS_RANDOM_H)
	#define EAP_CLASS_VISIBILITY_DSS_RANDOM_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_DSS_RANDOM_H 
	#define EAP_C_FUNC_VISIBILITY_DSS_RANDOM_H 
	#define EAP_FUNC_EXPORT_DSS_RANDOM_H 
	#define EAP_C_FUNC_EXPORT_DSS_RANDOM_H 
#elif defined(EAP_EXPORT_DSS_RANDOM_H)
	#define EAP_CLASS_VISIBILITY_DSS_RANDOM_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_DSS_RANDOM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_DSS_RANDOM_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_DSS_RANDOM_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_DSS_RANDOM_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_DSS_RANDOM_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_DSS_RANDOM_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_DSS_RANDOM_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_DSS_RANDOM_H 
	#define EAP_C_FUNC_EXPORT_DSS_RANDOM_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_tools.h"

#ifdef  __cplusplus
extern "C" {
#endif

EAP_C_FUNC_VISIBILITY_DSS_RANDOM_H eap_status_e dss_pseudo_random(abs_eap_am_tools_c * const am_tools, u8_t *out, u32_t out_length, u8_t *xkey, u32_t xkey_length);

#ifdef  __cplusplus
}
#endif

// End.
