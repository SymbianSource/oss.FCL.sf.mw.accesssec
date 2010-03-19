/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/wai_protocol_packet_header.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 16 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.2
*/



#if !defined(_WAI_PROTOCOL_PACKET_HEADER_H_)
#define _WAI_PROTOCOL_PACKET_HEADER_H_

#if defined(USE_WAPI_CORE)

#include "eap_tools.h"
#include "wapi_types.h"
#include "eap_general_header_base.h"

/** @file */


//----------------------------------------------------------------------------


/// This class defines header of WAI protocol packet.
/**
 * Here is a figure of header of WAI protocol packet.
 * Data follows wai_protocol_packet_header_c.
 * @code
 *  TLV-header:
 * 0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Version            |     Type      |    Subtype    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |            Reserved           |          Length               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    Packet sequence number     |Frag. Seg. No. |     Flag      |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * | Data ...                                                       
 * +-+-+-+-+-                                                       
 * @endcode
 * 
 * For details see <a href="../../../internal/doc/WAPI/WAPI_design.doc">WAPI_design.doc</a>.
 */
class EAP_EXPORT wai_protocol_packet_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// This is enumeration of masks of Flag field.
	enum flag_masks
	{
		m_flag_mask_fragment_exists = 0x01,
	};

	/// This is enumeration of sizes of fields.
	enum sizes
	{
		m_version_size = sizeof(u16_t),                 ///< This is size of Version 16-bit field.
		m_type_size = sizeof(u8_t),                     ///< This is size of Type 8-bit field.
		m_subtype_size = sizeof(u8_t),                  ///< This is size of Subtype 8-bit field.
		m_reserved_size = sizeof(u16_t),                ///< This is size of Reserved 16-bit field.
		m_length_size = sizeof(u16_t),                  ///< This is size of Length 16-bit field.
		m_packet_sequence_number_size = sizeof(u16_t),  ///< This is size of Packet sequence number 16-bit field.
		m_fragment_sequence_number_size = sizeof(u8_t), ///< This is size of Fragment sequence number 8-bit field.
		m_flag_size = sizeof(u8_t),                     ///< This is size of Flag 8-bit field.
	};

	/// This is enumeration of offsets to data fields.
	enum offsets
	{
		m_version_offset = 0ul,                                                                            ///< This is offset to Version 16-bit field.
		m_type_offset = m_version_offset+m_version_size,                                                   ///< This is offset to Type 8-bit field.
		m_subtype_offset = m_type_offset+m_type_size,                                                      ///< This is offset to Subtype 8-bit field.
		m_reserved_offset = m_subtype_offset+m_subtype_size,                                               ///< This is offset to Reserved 16-bit field.
		m_length_offset = m_reserved_offset+m_reserved_size,                                               ///< This is offset to Length 16-bit field.
		m_packet_sequence_number_offset = m_length_offset+m_length_size,                                   ///< This is offset to Packet sequence number 16-bit field.
		m_fragment_sequence_number_offset = m_packet_sequence_number_offset+m_packet_sequence_number_size, ///< This is offset to Fragment sequence number 8-bit field.
		m_flag_offset = m_fragment_sequence_number_offset+m_fragment_sequence_number_size,                 ///< This is offset to Flag 8-bit field.
		m_data_offset = m_flag_offset+m_flag_size,                                                         ///< This is offset to Data.
	};

	/**
	 * The destructor of the wai_protocol_packet_header_c class does nothing.
	 */
	virtual ~wai_protocol_packet_header_c();

	/**
	 * The constructor of the wai_protocol_packet_header_c class.
	 */
	wai_protocol_packet_header_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * The constructor of the wai_protocol_packet_header_c class simply initializes the attributes.
	 */
	wai_protocol_packet_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function sets the header buffer.
	 */
	eap_status_e set_header_buffer(
		void * const header_begin,
		const u32_t header_buffer_length);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function returns the Version value.
	 */
	wai_protocol_version_e get_version() const;

	/**
	 * This function returns the Type value.
	 */
	wai_protocol_type_e get_type() const;

	/**
	 * This function returns the Subtype value.
	 */
	wai_protocol_subtype_e get_subtype() const;

	/**
	 * This function returns the Reserved value.
	 */
	u16_t get_reserved() const;

	/**
	 * This function returns the Length value.
	 */
	u32_t get_length() const;

	/**
	 * This function returns the Packet sequence number value.
	 */
	u16_t get_packet_sequence_number() const;

	/**
	 * This function returns the Fragment sequence number value.
	 */
	u8_t get_fragment_sequence_number() const;

	/**
	 * This function returns the Flag value.
	 */
	u8_t get_flag() const;

	/**
	 * This function returns the header length of WAI protocol packet.
	 */
	static u32_t get_header_length();

	/**
	 * This function returns the data length of WAI protocol packet.
	 */
	u32_t get_data_length() const;

	/**
	 * This function returns pointer to the offset of data of WAI protocol packet.
	 * @param offset is the offset of queried data in bytes.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;


	/**
	 * This function returns pointer to the begin of data of WAI protocol packet.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_data(const u32_t contignuous_bytes) const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function checks the header is valid.
	 */
	eap_status_e check_header() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function sets the Version value.
	 */
	eap_status_e set_version(const wai_protocol_version_e version);

	/**
	 * This function sets the Type value.
	 */
	eap_status_e set_type(const wai_protocol_type_e type);

	/**
	 * This function sets the Subype value.
	 */
	eap_status_e set_subtype(const wai_protocol_subtype_e subtype);

	/**
	 * This function sets the Reserved value.
	 */
	eap_status_e set_reserved(const u16_t reserved);

	/**
	 * This function sets the Length value.
	 */
	eap_status_e set_length(const u32_t length);

	/**
	 * This function sets the Packet sequence number value.
	 */
	eap_status_e set_packet_sequence_number(const u16_t packet_sequence_number);

	/**
	 * This function sets the Fragment sequence number value.
	 */
	eap_status_e set_fragment_sequence_number(const u8_t fragment_sequence_number);

	/**
	 * This function sets the Flag value.
	 */
	eap_status_e set_flag(const u8_t flag);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	/**
	 * This function resets the WAI protocol packet header.
	 */
	eap_status_e reset_header();

	// 
	//--------------------------------------------------
}; // class wai_protocol_packet_header_c

//----------------------------------------------------------------------------------

/// Macro traces payload type and data.
#define WAI_PROTOCOL_PACKET_TRACE_HEADER(prefix, header, when_true_is_client) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v \n"))); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- buffer"), (header)->get_header_buffer((header)->get_header_buffer_length()), \
			(header)->get_header_buffer_length())); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- %s, %s (0x%08x): Version=%d, Type=%d, Subtype=%d=%s, Reserved=%d,\n"), \
			prefix, \
			((when_true_is_client) == true ? "client" : "server"), \
			(header)->get_header_buffer((header)->get_header_buffer_length()), \
			(header)->get_version(), \
			(header)->get_type(), \
			(header)->get_subtype(), \
			wapi_strings_c::get_wai_protocol_subtype_string((header)->get_subtype()), \
			(header)->get_reserved())); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- %s, %s (0x%08x): Length=%d, Packet sequence number=%d, Fragment sequence number=%d, Flag=%d, data length 0x%04x.\n"), \
			prefix, \
			((when_true_is_client) == true ? "client" : "server"), \
			(header)->get_header_buffer((header)->get_header_buffer_length()), \
			(header)->get_length(), \
			(header)->get_packet_sequence_number(), \
			(header)->get_fragment_sequence_number(), \
			(header)->get_flag(), \
			(header)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(wapi_strings_c::get_wai_protocol_subtype_string((header)->get_subtype()), \
			(header)->get_header_buffer((header)->get_header_buffer_length()), \
			(header)->get_header_buffer_length())); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ \n"))); \
	}

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_WAI_PROTOCOL_PACKET_HEADER_H_)



// End.
