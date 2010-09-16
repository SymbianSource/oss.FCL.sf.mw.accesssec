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

#if !defined(_EAP_DIAMETER_AVP_HEADER_H_)
#define _EAP_DIAMETER_AVP_HEADER_H_

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "eap_diameter_avp_code.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_DIAMETER_AVP_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_DIAMETER_AVP_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_DIAMETER_AVP_HEADER_H 
#elif defined(EAP_EXPORT_EAP_DIAMETER_AVP_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_DIAMETER_AVP_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_DIAMETER_AVP_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_DIAMETER_AVP_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_DIAMETER_AVP_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */

const u32_t TRACE_FLAGS_DIAMETER_ERROR = eap_am_tools_c::eap_trace_mask_error;

//----------------------------------------------------------------------------


/// This class defines header of Attribute-Value Pairs.
/**
 * Here is a figure of header of Attribute-Value Pairs.
 * Value data follows eap_diameter_avp_header_c.
 * @code
 *  AVP-header:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                           AVP Code                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |V|M|r r r r r r|                  AVP Length                   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Vendor-ID (optional)                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Data ....
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 * 
 * @code
 * The fields of this header are:
 * 32-bits AVP Code;                 This is a AVP Code.
 * 1-bit   flag vendor specific (V); Whether this AVP is vendor specific (1)
 * 1-bit   flag mandatory (M);       Whether support of the AVP is required (1).
 * 6-bits  reserved bits;            Unused bits must be zero.
 * 24-bits value AVP Length;         This is a length field, the length (in bytes) of the AVP header and data.
 * 32-bits Vendor-ID;                This is a optional Vendor-ID. The flag vendor specific (V) must be set too.
 * @endcode
 * 
 * See <a href="../../documentation/RFCs/draft-funk-eap-ttls-v0-00.txt">draft-funk-eap-ttls-v0-00.txt</a>.
 */
class EAP_CLASS_VISIBILITY_EAP_DIAMETER_AVP_HEADER_H eap_diameter_avp_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is enumeration of bit masks.
	enum bit_masks
	{
		m_flag_mask_vendor_specific_avp = 0x80,
		m_flag_mask_mandatory_avp       = 0x40,
		m_flag_mask_reserved_avp        = 0x3f,
	};


	//--------------------------------------------------
protected:
	//--------------------------------------------------

	/// This is enumeration of offsets to data fields.
	enum offsets
	{
		m_avp_code_offset = 0ul,                                         ///< This is offset to AVP Code 32-bit field.
		m_flags_offset = m_avp_code_offset+sizeof(u32_t),                ///< This is offset to flags 8-bit field.
		m_length_offset = m_flags_offset+sizeof(u8_t),                   ///< This is offset to length 24-bit field.
		m_vendor_id_or_data_offset = m_length_offset+(3ul*sizeof(u8_t)), ///< This is offset to vendor_specific id of data field.
		m_data_with_vendor_id_offset = m_vendor_id_or_data_offset+sizeof(u32_t), ///< This is offset to data field.
	};

	/// This is enumeration of sizes of data fields.
	enum avp_sizes
	{
		EAP_DIAMETER_AVP_MINIMUM_HEADER_LENGTH = m_vendor_id_or_data_offset,
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_diameter_avp_header_c class does nothing.
	 */
	virtual ~eap_diameter_avp_header_c();

	/**
	 * The constructor of the eap_diameter_avp_header_c class simply initializes the attributes.
	 */
	eap_diameter_avp_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	/**
	 * This function returns lengthof required padding.
	 */
	u32_t get_padding_length() const;


	/**
	 * This function returns the AVP Code.
	 */
	eap_diameter_avp_code_c get_avp_code() const;

	/**
	 * This function returns the AVP vendor specific flag.
	 */
	bool get_avp_flag_vendor_specific() const;

	/**
	 * This function returns the AVP mandatory flag.
	 */
	bool get_avp_flag_mandatory_avp() const;

	/**
	 * This function returns the AVP reserved flags.
	 */
	u8_t get_avp_flags_reserved() const;

	/**
	 * This function returns the length of AVP (header+data).
	 */
	u32_t get_length() const;

	/**
	 * This function returns the length of AVP data.
	 */
	u32_t get_data_length() const;

	/**
	 * This function returns the header length of AVP.
	 */
	static u32_t get_header_length(const bool include_vendor_specific);

	/**
	 * This function returns the header length of AVP.
	 */
	u32_t get_header_length() const;

	/**
	 * This function returns pointer to the offset of data of AVP.
	 * @param offset is the offset of queried data in bytes.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;


	/**
	 * This function returns pointer to the offset of data of AVP.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_data(const u32_t contignuous_bytes) const;


	/**
	 * This function return pointer to the next AVP header in the same buffer.
	 */
	u8_t * get_next_header() const;


	/**
	 * This function checks the header is valid.
	 */
	eap_status_e check_header() const;

	/**
	 * This function returns debug strings of the AVP Code.
	 */
	eap_const_string get_avp_code_string() const;

	/**
	 * This function sets the AVP Code.
	 */
	eap_status_e set_avp_code(const eap_diameter_avp_code_c code);

	/**
	 * This function sets the AVP vendor specific flag.
	 */
	eap_status_e set_avp_flag_vendor_specific(const bool vendor_specific);

	/**
	 * This function sets the AVP mandatory flag.
	 */
	eap_status_e set_avp_flag_mandatory_avp(const bool mandatory);

	/**
	 * This function sets the AVP mandatory flag.
	 */
	eap_status_e set_avp_flags_reserved();

	/**
	 * This function sets the AVP data length.
	 */
	eap_status_e set_data_length(const u32_t p_length);

	/**
	 * This function resets the AVP header.
	 */
	eap_status_e reset_header(const u16_t data_length);

	// 
	//--------------------------------------------------
}; // class eap_diameter_avp_header_c


//--------------------------------------------------

/// Macro traces payload type and data.
#define EAP_DIAMETER_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("%s (0x%08x): AVP code 0x%08x:0x%08x=%s, data length 0x%04x.\n"), \
			prefix, (payload)->get_header_buffer((payload)->get_length()), \
			(payload)->get_avp_code().get_vendor_id(), (payload)->get_avp_code().get_vendor_code(), \
			(payload)->get_avp_code_string(), (payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("payload"), (payload)->get_header_buffer((payload)->get_length()), \
			(payload)->get_length())); \
	}

//--------------------------------------------------

#endif //#if !defined(_EAP_DIAMETER_AVP_HEADER_H_)



// End.
