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





#if !defined( _ABS_EAP_AM_TOOLS_MEMORY_STORE_DATA_H_ )
#define _ABS_EAP_AM_TOOLS_MEMORY_STORE_DATA_H_


#include "eap_am_export.h"

/// This class is base class for data stored to memory store.
/**
 * Here are no real functions.
 */
class EAP_EXPORT abs_eap_am_memory_store_data_c
{
public:

	/**
	 * The destructor of the abs_eap_am_memory_store_data_c class does nothing special.
	 */
	EAP_FUNC_IMPORT virtual ~abs_eap_am_memory_store_data_c();

	/**
	 * The constructor of the abs_eap_am_memory_store_data_c does nothing special.
	 */
	EAP_FUNC_IMPORT abs_eap_am_memory_store_data_c();

};

#endif //#if !defined( _ABS_EAP_AM_TOOLS_MEMORY_STORE_DATA_H_ )



// End.
