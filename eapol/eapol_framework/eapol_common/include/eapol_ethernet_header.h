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
* %version: 6 %
*/

#if !defined(_EAP_ETHERNET_HEADER_H_)
#define _EAP_ETHERNET_HEADER_H_

#include "eap_tools.h"
#include "eapol_header.h"
#include "eap_general_header_base.h"
#include "eapol_ethernet_address.h"


/** @file */

/**
 * This is base class of Ethernet header used with EAPOL.
 * @code
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |          Destination address                                  |
 *  +-                             -+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                               |       Source address          |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-                             -+
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |             Type              |   Data ...                     
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_EXPORT eapol_ethernet_header_base_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	/**
	 * This enumeration defines the offsets of the Ethernet-header fields.
	 */
	enum offsets
	{
		m_destination_offset = 0ul,                                           ///< This is offset to destination address field.
		m_source_offset = m_destination_offset+EAPOL_ETHERNET_ADDRESS_LENGTH, ///< This is offset to source address field.
		m_type_offset = m_source_offset+EAPOL_ETHERNET_ADDRESS_LENGTH,        ///< This is offset to type field.
		m_data_offset = m_type_offset+sizeof(u16_t),                          ///< This is offset to data field.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	EAP_FUNC_IMPORT virtual ~eapol_ethernet_header_base_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of Ethernet-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_IMPORT eapol_ethernet_header_base_c(
			abs_eap_am_tools_c * const tools,
			void * const header_buffer,
			const u32_t header_buffer_length);

	/// This function returns pointer to the destination address of the Ethernet-packet.
	EAP_FUNC_IMPORT u8_t * get_destination() const;

	/// This function returns pointer to the source address of the Ethernet-packet.
	EAP_FUNC_IMPORT u8_t * get_source() const;

	/// This function returns length of the destination address of the Ethernet-packet.
	EAP_FUNC_IMPORT u32_t get_destination_length() const;

	/// This function returns length of the source address of the Ethernet-packet.
	EAP_FUNC_IMPORT u32_t get_source_length() const;

	/// This function returns the packet type field of Ethernet-header.
	EAP_FUNC_IMPORT u16_t get_type() const;

	/// This function returns pointer to the data of the Ethernet-packet.
	EAP_FUNC_IMPORT u8_t * get_data(const u32_t data_length) const;

	/// This function returns the length of the data of Ethernet-header.
	EAP_FUNC_IMPORT u32_t get_data_length() const;

	/// This function returns the header length of the Ethernet-packet.
	EAP_FUNC_IMPORT static u16_t get_header_length();

	/// This function sets the packet type field of the Ethernet-header.
	EAP_FUNC_IMPORT void set_type(const eapol_ethernet_type_e type);

	/// This function checks the validity of Ethernet-header.
	EAP_FUNC_IMPORT eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class eapol_ethernet_header_base_c





/// @{ This class can be removed. eapol_ethernet_header_base_c could be used instead. }
class EAP_EXPORT eapol_ethernet_header_rd_c
: public eapol_ethernet_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	EAP_FUNC_IMPORT virtual ~eapol_ethernet_header_rd_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of Ethernet-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_IMPORT eapol_ethernet_header_rd_c(
			abs_eap_am_tools_c * const tools,
			const u8_t * const header_buffer,
			const u32_t header_buffer_length);

	/// This function returns pointer to the header of the EAPOL-packet included in the Ethernet-packet.
	EAP_FUNC_IMPORT u8_t * get_eapol_header() const;

	// 
	//--------------------------------------------------
}; // class eapol_ethernet_header_rd_c



/// @{ This class can be removed. eapol_ethernet_header_base_c could be used instead. }
class EAP_EXPORT eapol_ethernet_header_wr_c
: public eapol_ethernet_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	EAP_FUNC_IMPORT virtual ~eapol_ethernet_header_wr_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of Ethernet-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_IMPORT eapol_ethernet_header_wr_c(
			abs_eap_am_tools_c * const tools,
			const u8_t * const header_buffer,
			const u32_t header_buffer_length);

	/// This function returns pointer to the header of the EAPOL-packet included in the Ethernet-packet.
	EAP_FUNC_IMPORT u8_t * get_eapol_header() const;

	/// This function returns pointer to the destination address of the Ethernet-packet.
	EAP_FUNC_IMPORT u8_t * get_destination();

	/// This function returns pointer to the source address of the Ethernet-packet.
	EAP_FUNC_IMPORT u8_t * get_source();

	/// This function resets the EAPOL-header.
	/// The type parameter is the type of Ethernet-packet.
	/// The buffer_length parameter is the length of the EAPOL-header and the following data buffer.
	EAP_FUNC_IMPORT void reset_header(const eapol_ethernet_type_e type, const u16_t buffer_length);

	// 
	//--------------------------------------------------
}; // class eapol_ethernet_header_wr_c



#endif //#if !defined(_EAP_ETHERNET_HEADER_H_)

//--------------------------------------------------



// End.
