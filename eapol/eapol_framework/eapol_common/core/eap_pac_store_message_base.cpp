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

#include "eap_am_tools.h"
#include "eap_am_export.h"
#include "eap_pac_store_message_base.h"

/**
 * The destructor of the eap_core class does nothing special.
 */
EAP_FUNC_EXPORT  eap_pac_store_message_base_c::~eap_pac_store_message_base_c()
{
}

/**
 * The constructor initializes member attributes using parameters passed to it.
 * @param tools is pointer to the tools class. @see abs_eap_am_tools_c.
 * @param partner is back pointer to object which created this object.
 * @param is_client_when_true indicates whether the network entity should act
 * as a client (true) or server (false), in terms of EAP-protocol
 * whether this network entity is EAP-supplicant (true) or EAP-authenticator (false).
 */
EAP_FUNC_EXPORT eap_pac_store_message_base_c::eap_pac_store_message_base_c()
{
}

//--------------------------------------------------
// End.
