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
#include "eap_am_tools.h"

#ifdef  __cplusplus
extern "C" {
#endif

EAP_C_FUNC_IMPORT eap_status_e dss_pseudo_random(abs_eap_am_tools_c * const am_tools, u8_t *out, u32_t out_length, u8_t *xkey, u32_t xkey_length);

#ifdef  __cplusplus
}
#endif

// End.
