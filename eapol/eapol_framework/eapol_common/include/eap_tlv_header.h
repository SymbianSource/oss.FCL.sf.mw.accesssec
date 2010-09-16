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

#if !defined(_EAP_TLV_HEADER_H_)
#define _EAP_TLV_HEADER_H_

#include "eap_am_types.h"
#include "eap_tools.h"
#include "eap_general_header_base.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_TLV_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TLV_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLV_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_TLV_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TLV_HEADER_H 
#elif defined(EAP_EXPORT_EAP_TLV_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_TLV_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLV_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_TLV_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_TLV_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_TLV_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_TLV_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_TLV_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_TLV_HEADER_H 
#endif
// End: added by script change_export_macros.sh.


/** @file */


typedef u32_t eap_tlv_type_t;

const eap_tlv_type_t eap_tlv_type_none = 0ul;

//----------------------------------------------------------------------------


/// This class defines header of Attribute-Value Pairs.
/**
 * Here is a figure of header of Attribute-Value Pairs.
 * Value data follows eap_tlv_header_c.
 * @code
 *  EAP-TLV-header:
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Type                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             Length                            |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                              Value...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * @endcode
 * 
 * @code
 * The fields of this header are:
 * 32-bits Type;                   This is a type of value.
 * 32-bits value length (Length);  This is a length field, the length (in bytes) of the following value.
 * @endcode
 * 
 */
class EAP_CLASS_VISIBILITY_EAP_TLV_HEADER_H eap_tlv_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	/// This is enumeration of offsets to data fields.
	enum offsets
	{
		m_type_offset = 0ul,                           ///< This is offset to fags and tlv type 32-bit field.
		m_length_offset = m_type_offset+sizeof(u32_t), ///< This is offset to length 32-bit field.
		m_data_offset = m_length_offset+sizeof(u32_t), ///< This is offset to data field.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/**
	 * The destructor of the eap_tlv_header_c class does nothing.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H virtual ~eap_tlv_header_c();

	/**
	 * The constructor of the eap_tlv_header_c class simply initializes the attributes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H eap_tlv_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	/**
	 * This function returns the type.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H eap_tlv_type_t get_type() const;

	/**
	 * This function returns the data length of value.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H u32_t get_value_length() const;

	/**
	 * This function returns the header length of TLV.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H static u32_t get_header_length();

	/**
	 * This function returns pointer to the offset of value.
	 * @param offset is the offset of queried data in bytes.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H u8_t * get_value_offset(const u32_t offset, const u32_t contignuous_bytes) const;


	/**
	 * This function returns pointer to begin of value.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H u8_t * get_value(const u32_t contignuous_bytes) const;


	/**
	 * This function checks the header is valid.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H eap_status_e check_header() const;

	/**
	 * This function returns the type.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H eap_status_e set_type(const eap_tlv_type_t type);

	/**
	 * This function sets the value length.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H eap_status_e set_value_length(const u32_t value_length);

	/**
	 * This function resets the TLV header.
	 */
	EAP_FUNC_VISIBILITY_EAP_TLV_HEADER_H eap_status_e reset_header(
		const eap_tlv_type_t type,
		const u32_t value_length);

	// 
	//--------------------------------------------------
}; // class eap_tlv_header_c


//--------------------------------------------------

#endif //#if !defined(_EAP_TLV_HEADER_H_)



// End.
