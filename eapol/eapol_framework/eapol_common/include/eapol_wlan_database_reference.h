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



#if !defined(_EAPOL_WLAN_DATABASE_REFERENCE_H_)
#define _EAPOL_WLAN_DATABASE_REFERENCE_H_

//--------------------------------------------------

#include "eap_am_export.h"
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
