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
* Description:  defines header of Attribute-Value Pairs used in protected setup.
*
*/

/*
* %version: 9.1.2 %
*/

#if !defined(_SIMPLE_CONFIG_TLV_HEADER_H_)
#define _SIMPLE_CONFIG_TLV_HEADER_H_

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "simple_config_attribute_type.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H 
#elif defined(EAP_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H)
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H 
	#define EAP_C_FUNC_EXPORT_SIMPLE_CONFIG_TLV_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */


//----------------------------------------------------------------------------


/// This class defines header of Attribute-Value Pairs.
/**
 * Here is a figure of header of Attribute-Value Pairs.
 * Value data follows simple_config_tlv_header_c.
 * @code
 *  TLV-header:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       Attribute Type          |         Data Length           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Data ... 
 * +-+-+-+-+-+-+-+-+-+-
 * @endcode
 * 
 * @code
 * The fields of this header are:
 * 16-bits Attribute Type          This is a TLV type.
 * 16-bits Data Length;            This is a length field, the length (in bytes) of the following Data.
 * @endcode
 */
class EAP_CLASS_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H simple_config_tlv_header_c
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
	enum offsets
	{
		m_tlv_type_offset = 0ul,                           ///< This is offset to tlv type 16-bit field.
		m_length_offset = m_tlv_type_offset+sizeof(u16_t), ///< This is offset to length 16-bit field.
		m_data_offset = m_length_offset+sizeof(u16_t),     ///< This is offset to data field.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the simple_config_tlv_header_c class does nothing.
	 */
	virtual ~simple_config_tlv_header_c();

	/**
	 * The constructor of the simple_config_tlv_header_c class simply initializes the attributes.
	 */
	simple_config_tlv_header_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * The constructor of the simple_config_tlv_header_c class simply initializes the attributes.
	 */
	simple_config_tlv_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	/**
	 * This function returns the TLV type flag.
	 */
	simple_config_Attribute_Type_e get_tlv_type() const;

	/**
	 * This function returns the length of TLV (header+data).
	 */
	u32_t get_length() const;

	/**
	 * This function returns the data length of TLV.
	 */
	u16_t get_data_length() const;

	/**
	 * This function returns the header length of TLV.
	 */
	EAP_FUNC_VISIBILITY_SIMPLE_CONFIG_TLV_HEADER_H static u32_t get_header_length();

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
	eap_const_string get_tlv_type_string() const;

	/**
	 * This function sets the TLV type flag.
	 */
	void set_tlv_type(simple_config_Attribute_Type_e type);

	/**
	 * This function sets the TLV data length.
	 */
	void set_data_length(const u16_t p_length);

	/**
	 * This function resets the TLV header.
	 */
	void reset_header(const u16_t buffer_length);

	// 
	//--------------------------------------------------
}; // class simple_config_tlv_header_c


//--------------------------------------------------

/// Macro traces payload type and data.
#define SIMPLE_CONFIG_TLV_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n"))); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- %s (0x%08x): TLV type 0x%08x=%s, data length 0x%04x.\n"), \
			prefix, (payload)->get_header_buffer((payload)->get_length()), \
			(payload)->get_tlv_type(), \
			(payload)->get_tlv_type_string(), (payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- data"), (payload)->get_data((payload)->get_data_length()), \
			(payload)->get_data_length())); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - \n"))); \
	}

//--------------------------------------------------

#endif //#if !defined(_SIMPLE_CONFIG_TLV_HEADER_H_)



// End.
