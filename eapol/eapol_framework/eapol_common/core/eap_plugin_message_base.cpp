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
* Description:  virtual functions of EAP-plugin interface.
*
*/

/*
* %version: 3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 769 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)

#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "eap_plugin_message_base.h"

/**
 * The destructor of the eap_core class does nothing special.
 */
EAP_FUNC_EXPORT  eap_plugin_message_base_c::~eap_plugin_message_base_c()
{
}

/**
 * The constructor initializes member attributes.
 */
EAP_FUNC_EXPORT eap_plugin_message_base_c::eap_plugin_message_base_c()
{
}

//--------------------------------------------------
// End.
