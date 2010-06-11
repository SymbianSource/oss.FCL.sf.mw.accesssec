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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 108 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_radius_mac_attributes.h"


//--------------------------------------------------

eap_radius_MAC_attributes_c::~eap_radius_MAC_attributes_c()
{
}

eap_radius_MAC_attributes_c::eap_radius_MAC_attributes_c()
	: m_MAC(0)
	, m_MAC_size(0)
	, m_data(0)
	, m_data_length(0u)
{
}

eap_radius_MAC_attributes_c::eap_radius_MAC_attributes_c(
	u8_t * MAC,
	u32_t MAC_size,
	u8_t * const EAP_data,
	u32_t EAP_data_length)
	: m_MAC(MAC)
	, m_MAC_size(MAC_size)
	, m_data(EAP_data)
	, m_data_length(EAP_data_length)
{
}

void eap_radius_MAC_attributes_c::init(
	u8_t * MAC,
	u32_t MAC_size,
	u8_t * const EAP_data,
	u32_t EAP_data_length)
{
	m_MAC = (MAC);
	m_MAC_size = (MAC_size);
	m_data = (EAP_data);
	m_data_length = (EAP_data_length);
}

u8_t * eap_radius_MAC_attributes_c::get_MAC() const
{
	return m_MAC;
}

void eap_radius_MAC_attributes_c::set_MAC(u8_t * MAC)
{
	m_MAC = MAC;
}

u32_t eap_radius_MAC_attributes_c::get_MAC_size() const
{
	return m_MAC_size;
}

eap_radius_MAC_attributes_c * eap_radius_MAC_attributes_c::copy() const
{
	return new eap_radius_MAC_attributes_c(
		m_MAC,
		m_MAC_size,
		m_data,
		m_data_length);
}

u8_t * eap_radius_MAC_attributes_c::get_data() const
{
	return m_data;
}

u32_t eap_radius_MAC_attributes_c::get_data_length()
{
	return m_data_length;
}

void eap_radius_MAC_attributes_c::set_data(u8_t * const data)
{
	m_data = data;
}

//--------------------------------------------------



// End.
