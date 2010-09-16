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

#if !defined(_TLS_PEAP_TLV_HEADER_H_)
#define _TLS_PEAP_TLV_HEADER_H_

#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_TLS_PEAP_TLV_HEADER_H)
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TLV_HEADER_H 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TLV_HEADER_H 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TLV_HEADER_H 
#elif defined(EAP_EXPORT_TLS_PEAP_TLV_HEADER_H)
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TLV_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TLV_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TLV_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_TLS_PEAP_TLV_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_TLS_PEAP_TLV_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_TLS_PEAP_TLV_HEADER_H 
	#define EAP_C_FUNC_EXPORT_TLS_PEAP_TLV_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */


/**
 * This is enumeration of PEAP Type-Length-Value (TLV) values.
 * See <a href="../../type/tls_peap/documentation/draft-puthenkulam-eap-binding-03.txt">draft-puthenkulam-eap-binding-03.txt</a>
 * and <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">draft-josefsson-pppext-eap-tls-eap-07.txt</a>.
 */
enum tls_peap_tlv_type_e
{
	tls_peap_tlv_type_reserved_zero       = 0,
	tls_peap_tlv_type_reserved_one        = 1,
	tls_peap_tlv_type_reserved_two        = 2,
	tls_peap_tlv_type_result              = 3,  ///< RESULT_TLV
	tls_peap_tlv_type_nak                 = 4,  ///< NAK_TLV
	tls_peap_tlv_type_crypto_binding      = 5,  ///< CRYPTO_BINDING_TLV
	tls_peap_tlv_eap_payload              = 8,  ///< EAP-Payload TLV
	tls_peap_tlv_type_intermediate_result = 10, ///< Intermediate Result TLV
	tls_peap_tlv_type_none                = 255,
};


enum tls_peap_tlv_type_crypto_binding_type_e
{
	tls_peap_tlv_type_crypto_binding_request = 0,
	tls_peap_tlv_type_crypto_binding_response = 1,
	tls_peap_tlv_type_crypto_binding_none = 0xff,
};

/**
 * This is enumeration of status values of result TLV.
 * See <a href="../../type/tls_peap/documentation/draft-puthenkulam-eap-binding-03.txt">draft-puthenkulam-eap-binding-03.txt</a>
 * and <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">draft-josefsson-pppext-eap-tls-eap-07.txt</a>.
 */
enum tls_peap_tlv_status_e
{
	tls_peap_tlv_status_none = 0,
	tls_peap_tlv_status_success = 1,
	tls_peap_tlv_status_failure = 2,
};


//----------------------------------------------------------------------------


/// This class defines header of Attribute-Value Pairs.
/**
 * Here is a figure of header of Attribute-Value Pairs.
 * Value data follows tls_peap_tlv_header_c.
 * @code
 *  TLV-header:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |M|R|         TLV Type          |            Length             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Value...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 * 
 * @code
 * The fields of this header are:
 * 1-bit   flag mandatory tlv (M); Whether this TLV is mandatory (1)
 * 1-bit   flag reserved (R);      This is a reserved field, this is zero.
 * 14-bits TLV Type;               This is a TLV type.
 * 16-bits value length (Length);  This is a length field, the length (in bytes) of the following value.
 * @endcode
 * 
 * See <a href="../../type/tls_peap/documentation/draft-puthenkulam-eap-binding-03.txt">draft-puthenkulam-eap-binding-03.txt</a>
 * and <a href="../../type/tls_peap/documentation/draft-josefsson-pppext-eap-tls-eap-07.txt">draft-josefsson-pppext-eap-tls-eap-07.txt</a>.
 */
class EAP_CLASS_VISIBILITY_TLS_PEAP_TLV_HEADER_H tls_peap_tlv_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/// This is enumeration of bit masks.
	enum bit_masks
	{
		m_flag_mask_mandatory_tlv = 0x80,
		m_flag_mask_reserved = 0x40,
	};

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	/// This is enumeration of offsets to data fields.
	enum offsets
	{
		m_flags_and_tlv_type_offset = 0ul,                           ///< This is offset to fags and tlv type 16-bit field.
		m_length_offset = m_flags_and_tlv_type_offset+sizeof(u16_t), ///< This is offset to length 16-bit field.
		m_data_offset = m_length_offset+sizeof(u16_t),               ///< This is offset to data field.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the tls_peap_tlv_header_c class does nothing.
	 */
	virtual ~tls_peap_tlv_header_c();

	/**
	 * The constructor of the tls_peap_tlv_header_c class simply initializes the attributes.
	 */
	tls_peap_tlv_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	/**
	 * This function returns the TLV type flag.
	 */
	tls_peap_tlv_type_e get_flag_tlv_type() const;

	/**
	 * This function returns the TLV mandatory flag.
	 */
	bool get_flag_mandatory_tlv() const;

	/**
	 * This function returns the TLV reserved flag.
	 */
	bool get_flag_reserved() const;

	/**
	 * This function returns the data length of TLV.
	 */
	u16_t get_data_length() const;

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
	eap_const_string get_tlv_type_string() const;

	/**
	 * This function sets the TLV type flag.
	 */
	void set_flag_tlv_type(tls_peap_tlv_type_e type);

	/**
	 * This function sets the TLV reserved flag.
	 */
	void set_flag_reserved(bool reserved);

	/**
	 * This function sets the TLV manadtory flag.
	 */
	void set_flag_mandatory_tlv(const bool mandatory_when_true);

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
}; // class tls_peap_tlv_header_c

//--------------------------------------------------

/// Macro traces payload type and data.
#define TLS_PEAP_TLV_TRACE_PAYLOAD(prefix, payload) \
	{ \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v v \n"))); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("%s (0x%08x): M=%d, R=%d, TLV type 0x%08x=%s, data length 0x%04x.\n"), \
			prefix, (payload)->get_header_buffer((payload)->get_data_length()), \
			(payload)->get_flag_mandatory_tlv(), \
			(payload)->get_flag_reserved(), \
			(payload)->get_flag_tlv_type(), \
			(payload)->get_tlv_type_string(), \
			(payload)->get_data_length())); \
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("data"), (payload)->get_data((payload)->get_data_length()), \
			(payload)->get_data_length())); \
		EAP_TRACE_DEBUG( \
			m_am_tools, TRACE_FLAGS_DEFAULT|TRACE_TEST_VECTORS, \
			(EAPL("^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ ^ \n"))); \
	}

//--------------------------------------------------

#endif //#if !defined(_TLS_PEAP_TLV_HEADER_H_)



// End.
