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
* %version: 5 %
*/

#include "eap_loaded_type.h"
#include "eap_expanded_type.h"

/** @file */

//--------------------------------------------------

eap_loaded_type_c::eap_loaded_type_c(
	abs_eap_am_tools_c * const tools,
	CEapTypePlugin * const type_plugin,
	const eap_type_value_e eap_type,
	const u32_t index_type,
	const u32_t index)
	: m_am_tools(tools)
	, m_type_plugin(type_plugin)
	, m_eap_type(eap_type)
	, m_index_type(index_type)
	, m_index(index)
{
}

//--------------------------------------------------

eap_loaded_type_c::~eap_loaded_type_c()
{
	delete m_type_plugin;
}

//--------------------------------------------------

i32_t eap_loaded_type_c::compare(const eap_loaded_type_c * const right)
{
	if (get_index_type() != right->get_index_type())
	{
		return static_cast<i32_t>(get_index_type()) - static_cast<i32_t>(right->get_index_type());
	}
	else if (get_index() != right->get_index())
	{
		return static_cast<i32_t>(get_index()) - static_cast<i32_t>(right->get_index());
	}
	else
	{
		// Compares the EAP-type.
		return get_eap_type().compare(&(right->get_eap_type()));
	}
}

//--------------------------------------------------

CEapTypePlugin * eap_loaded_type_c::get_type_plugin()
{
	return m_type_plugin;
}

//--------------------------------------------------

eap_type_value_e eap_loaded_type_c::get_eap_type() const
{
	return m_eap_type;
}

//--------------------------------------------------

u32_t eap_loaded_type_c::get_index_type() const
{
	return m_index_type;
}

//--------------------------------------------------

u32_t eap_loaded_type_c::get_index() const
{
	return m_index;
}

//--------------------------------------------------
// End
