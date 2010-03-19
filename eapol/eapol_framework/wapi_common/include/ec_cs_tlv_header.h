/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/ec_cs_tlv_header.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 12 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright � 2001-2009 Nokia.  All rights reserved.
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



#if !defined(_EC_CS_TLV_HEADER_H_)
#define _EC_CS_TLV_HEADER_H_

#if defined(USE_WAPI_CORE)

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "ec_cs_types.h"

/** @file */


//----------------------------------------------------------------------------


/// This class defines header of Attribute-Value Pairs.
/**
 * Here is a figure of header of Attribute-Value Pairs.
 * Value data follows ec_cs_tlv_header_c.
 * @code
 *  TLV-header:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |             Type              |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Value...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 * 
 * @code
 * The fields of this header are:
 * 16-bits Type;                   This is a TLV type.
 * 16-bits value length (Length);  This is a length field, the length (in bytes) of the following value.
 * @endcode
 * 
 * For details see <a href="../../../internal/doc/WAPI/WAPI_design.doc">WAPI_design.doc</a>.
 */
class EAP_EXPORT ec_cs_tlv_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	/// This is enumeration of offsets to data fields.
	enum sizes
	{
		m_type_size = sizeof(u16_t),    ///< This is size of type 16-bit field.
		m_length_size = sizeof(u16_t), ///< This is size of length 16-bit field.
	};

	/// This is enumeration of offsets to data fields.
	enum offsets
	{
		m_type_offset = 0ul,                           ///< This is offset to type 16-bit field.
		m_length_offset = m_type_offset+m_type_size,   ///< This is offset to length 16-bit field.
		m_data_offset = m_length_offset+m_length_size, ///< This is offset to data field.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the ec_cs_tlv_header_c class does nothing.
	 */
	virtual ~ec_cs_tlv_header_c();

	/**
	 * The constructor of the ec_cs_tlv_header_c class simply initializes the attributes.
	 */
	ec_cs_tlv_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	/**
	 * This function returns the TLV Type.
	 */
	ec_cs_tlv_type_e get_type() const;

	/**
	 * This function returns the data length of TLV.
	 */
	u32_t get_data_length() const;

	/**
	 * This function returns the header length of TLV.
	 */
	static u32_t get_header_length();

	/**
	 * This function returns pointer to the offset of data of TLV.
	 * @param offset is the offset of queried data in bytes.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_data_offset(const u32_t offset, const u32_t contignuous_bytes) const;


	/**
	 * This function returns pointer to the offset of data of TLV.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_data(const u32_t contignuous_bytes) const;


	/**
	 * This function return pointer to the next TLV header in the same buffer.
	 */
	u8_t * get_next_header() const;


	/**
	 * This function checks the header is valid.
	 */
	eap_status_e check_header() const;

	/**
	 * This function returns debug strings of the TLV type.
	 */
	static eap_const_string get_tlv_string(const ec_cs_tlv_type_e type);

	/**
	 * This function returns debug strings of the TLV type.
	 */
	eap_const_string get_tlv_string() const;

	/**
	 * This function sets the TLV Type.
	 */
	eap_status_e set_type(const ec_cs_tlv_type_e type);

	/**
	 * This function sets the TLV data length.
	 */
	eap_status_e set_data_length(const u32_t p_length);

	/**
	 * This function resets the TLV header.
	 */
	eap_status_e reset_header();

	/**
	 * This function resets the TLV header object.
	 */
	eap_status_e reset();

	// 
	//--------------------------------------------------
}; // class ec_cs_tlv_header_c

//----------------------------------------------------------------------------------

/// Macro traces payload type and data.
#define EC_CS_TLV_TRACE_PAYLOAD(prefix, payload, when_true_is_client) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v \n"))); \
		if ((payload) != 0 && (payload)->get_is_valid() == true)									\
		{ \
			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
				(EAPL("- buffer"), (payload)->get_header_buffer((payload)->get_header_buffer_length()), \
				 (payload)->get_header_buffer_length()));				\
			EAP_TRACE_DEBUG(											\
				m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,		\
				(EAPL("- %s %s (0x%08x): TLV type 0x%04x=%s, data length 0x%04x.\n"), \
				 prefix,												\
				 ((when_true_is_client) == true ? "client" : "server"), \
				 (payload)->get_header_buffer((payload)->get_data_length()), \
				 (payload)->get_type(),									\
				 (payload)->get_tlv_string(),							\
				 (payload)->get_data_length()));						\
			EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
				((payload)->get_tlv_string(), (payload)->get_data((payload)->get_data_length()), \
				 (payload)->get_data_length()));						\
		} \
		else \
		{ \
			EAP_TRACE_DEBUG(									\
				m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS,		\
				(EAPL("payload=0x%08x is illegal.\n"), payload));				\
		} \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ \n"))); \
	}

//----------------------------------------------------------------------------------

#endif //#if defined(USE_WAPI_CORE)

#endif //#if !defined(_EC_CS_TLV_HEADER_H_)



// End.
