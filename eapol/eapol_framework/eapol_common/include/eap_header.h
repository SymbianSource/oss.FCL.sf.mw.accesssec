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

#if !defined(_EAP_HEADER_H_)
#define _EAP_HEADER_H_


#include "eap_general_header_base.h"
#include "eap_expanded_type.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_HEADER_H 
	#define EAP_FUNC_EXPORT_EAP_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_HEADER_H 
#elif defined(EAP_EXPORT_EAP_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAP_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAP_HEADER_H 
#endif
// End: added by script change_export_macros.sh.



/** @file */

//-----------------------------------------------------------------------------------------

/** This is base class defining the EAP-packet header.
 * @code
 *  Original EAP-header.
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type         |    Type data ...
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  0                   1                   2                   3
 *  
 *  EAP-header with expanded type field.
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Code      |  Identifier   |            Length             |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type         |                Vendor-Id                      |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                        Vendor-Type                            |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |  Type data ...
 *  +-+-+-+-+-+-+-+-+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAP_HEADER_H eap_header_base_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	/**
	 * This enumeration defines the offsets of the EAP-header fields.
	 */
	enum offsets
	{
		m_code_offset = 0ul,                                ///< This is offset to code field.
		m_identifier_offset = m_code_offset+sizeof(u8_t),   ///< This is offset to identifier field.
		m_length_offset = m_identifier_offset+sizeof(u8_t), ///< This is offset to length field.

		m_type_offset = m_length_offset+sizeof(u16_t),      ///< This is offset to optional type field.
		m_data_offset = m_type_offset+sizeof(u8_t),         ///< This is offset to optional data field.

		m_exp_ietf_type_offset = 0ul,                                                            ///< This is offset of extented type IETF type field in the Extepanded Type field.
		m_exp_vendor_id_offset = m_exp_ietf_type_offset+eap_expanded_type_c::m_ietf_type_size,   ///< This is offset of extented type vendor ID field in the Extepanded Type field.
		m_exp_vendor_type_offset = m_exp_vendor_id_offset+eap_expanded_type_c::m_vendor_id_size, ///< This is offset of extented type vendor type field in the Extepanded Type field.
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	/// Destructor does nothing special.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H virtual ~eap_header_base_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of EAP-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_header_base_c(
		abs_eap_am_tools_c * const tools,
		void * const header_buffer,
		const u32_t header_buffer_length);

	/// This function returns the header length of the EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H static u32_t get_header_length();

	/// This function returns the length of the ietf type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H static u32_t get_ietf_type_field_length();

	/// This function returns the length of the extented type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H static u32_t get_expanded_type_field_length();

	/// This function returns the offset of the IETF type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H static u32_t get_expanded_ietf_type_offset();

	/// This function returns the offset of the vendor ID of type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H static u32_t get_expanded_vendor_id_offset();

	/// This function returns the offset of the vendor type of type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H static u32_t get_expanded_vendor_type_offset();

	/// This function returns the offset of the start of the type data.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H static u32_t get_type_data_start_offset(
		const bool expanded_type_when_true);


	/// This function returns the code field of EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_code_value_e get_code() const;

	/// This function returns the identifier field of EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u8_t get_identifier() const;

	/// This function returns the length field of EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u16_t get_length() const;

	/// This function returns the IETF type field of EAP-header.
	/// This means the first 8-bits of type field, whether it is short or expanded type.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_type_ietf_values_e get_ietf_type() const;

	/// This function returns the type field of EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_type_value_e get_type() const;

	/// This function returns the length of type field of EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u32_t get_type_field_length() const;

	/// This function returns the type data length of EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u16_t get_type_data_length() const;

	/// This function returns the data length of EAP-packet.
	/// The data length includes type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u16_t get_data_length() const;

	/// This function returns the pointer to the offset of the type data field of EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u8_t * get_type_data_offset(
		const u32_t p_offset, const u32_t p_continuous_bytes) const;

	/// This function returns the pointer to the offset of the data field of EAP-packet.
	/// Data field includes type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u8_t * get_data_offset(
		const u32_t p_offset, const u32_t p_continuous_bytes) const;

	/// This function returns the pointer to the type data field of EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u8_t * get_type_data(
		const u32_t p_continuous_bytes) const;

	/// This function returns the pointer to the data field of EAP-packet.
	/// Data field includes type field.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u8_t * get_data(
		const u32_t p_continuous_bytes) const;

	/// This function sets the code field of the EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H void set_code(const eap_code_value_e p_code);

	/// This function sets the identifier field of the EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H void set_identifier(const u8_t p_identifier);

	/// This function sets the length field of the EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H void set_length(
		const u16_t p_length,
		const bool expanded_type_when_true);

	/// This function sets the length field of the EAP-header using the length of the type data.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H void set_type_data_length(
		const u16_t p_length,
		const bool expanded_type_when_true);

	/// This function sets the type field of the EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_status_e set_type(
		const eap_type_value_e p_type,
		const bool expanded_type_when_true);

	/// This function returns debug string of the code of the EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_const_string get_code_string() const;

	/// This function returns debug string of the type of the EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_const_string get_type_string() const;

	/// This function checks the validity of EAP-header.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_status_e check_header() const;

	// 
	//--------------------------------------------------
}; // class eap_header_c


//-----------------------------------------------------------------------------------------


/// This class is read only EAP-packet header.
/// @{ This class can be removed. eap_header_base_c could be used instead. }
class EAP_CLASS_VISIBILITY_EAP_HEADER_H eap_header_rd_c
: public eap_header_base_c
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
	EAP_FUNC_VISIBILITY_EAP_HEADER_H virtual ~eap_header_rd_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of EAP-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_header_rd_c(
		abs_eap_am_tools_c * const tools,
		u8_t * const header_buffer,
		const u32_t header_buffer_length);


	// 
	//--------------------------------------------------
}; // class eap_header_rd_c


//-----------------------------------------------------------------------------------------


/// This class is read and write EAP-packet header.
/// @{ This class can be removed. eap_header_base_c could be used instead. }
class EAP_CLASS_VISIBILITY_EAP_HEADER_H eap_header_wr_c
: public eap_header_base_c
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
	EAP_FUNC_VISIBILITY_EAP_HEADER_H virtual ~eap_header_wr_c();

	/// Constructor does nothing special.
	/// The tools parameter is pointer to tools object.
	/// The header_buffer parameter is pointer to buffer of EAP-packet including header and data.
	/// The header_buffer_length parameter is length of the header_buffer.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H eap_header_wr_c(
		abs_eap_am_tools_c * const tools,
		u8_t * const header_buffer,
		const u32_t header_buffer_length);


	/// This function returns the pointer to the type data field of EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u8_t * get_type_data(
		const u32_t p_continuous_bytes) const;

	/// This function returns the pointer to the offset of the type data field of EAP-packet.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H u8_t * get_type_data_offset(
		const u32_t p_offset,
		const u32_t p_continuous_bytes) const;

	/// This function resets the EAP-header.
	/// The buffer_length parameter is the length of the EAP-header and the following data buffer.
	EAP_FUNC_VISIBILITY_EAP_HEADER_H void reset_header(
		const u16_t buffer_length,
		const bool expanded_type_when_true);

	// 
	//--------------------------------------------------
}; // class eap_header_c


//-----------------------------------------------------------------------------------------



#endif //#if !defined(_EAP_HEADER_H_)

//--------------------------------------------------



// End.
