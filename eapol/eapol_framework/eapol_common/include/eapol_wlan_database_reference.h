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

#if !defined(_EAPOL_WLAN_DATABASE_REFERENCE_H_)
#define _EAPOL_WLAN_DATABASE_REFERENCE_H_

//--------------------------------------------------

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H 
#elif defined(EAP_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_WLAN_DATABASE_REFERENCE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_WLAN_DATABASE_REFERENCE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_am_types.h"
#include "eap_status.h"

class abs_eap_am_tools_c;


struct eapol_wlan_database_reference_values_s
{
	u32_t m_database_index_type;

	u32_t m_database_index;
};




#endif //#if !defined(_EAPOL_WLAN_DATABASE_REFERENCE_H_)

//--------------------------------------------------


// End.
