/*
* Copyright (c) 2008 Nokia Corporation and/or its subsidiary(-ies).
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

#if !defined(_ASN1_TYPE_H_)
#define _ASN1_TYPE_H_

#include "eap_variable_data.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ASN1_DER_TYPE_H)
	#define EAP_CLASS_VISIBILITY_ASN1_DER_TYPE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H 
	#define EAP_C_FUNC_VISIBILITY_ASN1_DER_TYPE_H 
	#define EAP_FUNC_EXPORT_ASN1_DER_TYPE_H 
	#define EAP_C_FUNC_EXPORT_ASN1_DER_TYPE_H 
#elif defined(EAP_EXPORT_ASN1_DER_TYPE_H)
	#define EAP_CLASS_VISIBILITY_ASN1_DER_TYPE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ASN1_DER_TYPE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ASN1_DER_TYPE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ASN1_DER_TYPE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ASN1_DER_TYPE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ASN1_DER_TYPE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ASN1_DER_TYPE_H 
	#define EAP_C_FUNC_EXPORT_ASN1_DER_TYPE_H 
#endif
// End: added by script change_export_macros.sh.
#include "eap_array.h"

//--------------------------------------------------

class asn1_type_const_c;

//--------------------------------------------------

class EAP_CLASS_VISIBILITY_ASN1_DER_TYPE_H asn1_der_type_c
{
	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum asn1_class_e
	{
		asn1_class_universal        = 0x00,
		asn1_class_application      = 0x40,
		asn1_class_context_specific = 0x80,
		asn1_class_private          = 0xC0,

		asn1_class_none = 0xffffffff,
	};

	enum asn1_pc_e
	{
		asn1_pc_primitive   = 0x00,
		asn1_pc_constructed = 0x20,

		asn1_pc_none = 0xffffffff,
	};

	enum asn1_tag_e
	{
		asn1_tag_end_of_content = 0,
		asn1_tag_boolean = 1,
		asn1_tag_integer = 2,
		asn1_tag_bit_string = 3,
		asn1_tag_octet_string = 4,
		asn1_tag_null = 5,
		asn1_tag_object_identifier = 6,
		asn1_tag_object_descriptor = 7,
		asn1_tag_external = 8,
		asn1_tag_real = 9,
		asn1_tag_enumerated = 10,
		asn1_tag_empedded_pdv = 11,
		asn1_tag_utf8_string = 12,
		asn1_tag_relative_oid = 13,
		asn1_tag_unknown_14 = 14,
		asn1_tag_unknown_15 = 15,
		asn1_tag_sequence = 16,
		asn1_tag_set = 17,
		asn1_tag_numeric_string = 18,
		asn1_tag_printable_string = 19,
		asn1_tag_t61_string = 20,
		asn1_tag_videotex_string = 21,
		asn1_tag_ia5_string = 22,
		asn1_tag_utc_time = 23,
		asn1_tag_unknown_24 = 24,
		asn1_tag_graphic_string = 25,
		asn1_tag_visible_string = 26,
		asn1_tag_general_string = 27,
		asn1_tag_universal_string = 28,
		asn1_tag_character_string = 29,
		asn1_tag_bmp_string = 30,

		asn1_tag_extented = 0xfffffffe,

		asn1_tag_none = 0xffffffff,
	};

	enum asn1_identifier_mask_e
	{
		asn1_identifier_mask_class = 0xC0,
		asn1_identifier_mask_pc    = 0x20,
		asn1_identifier_mask_tag   = 0x1F,
		asn1_high_bit_mask_tag     = 0x80,
	};

	enum asn1_identifier_const_e
	{
		asn1_identifier_const_simple_tag_size   = sizeof(u8_t),
		asn1_identifier_const_short_length_size = sizeof(u8_t),
		asn1_length_field_base = 256ul,
	};


	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H virtual ~asn1_der_type_c();

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H asn1_der_type_c(
		abs_eap_am_tools_c * const tools);

	/**
	 * The get_is_valid() function returns the status of the asn1_der_type_c object.
	 * @return True indicates the object is initialized.
	 */
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H bool get_is_valid() const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H u32_t get_index() const;

	/**
	 * The decode() function decodes ASN.1/DER data.
	 * @return eap_status_ok indicates successfull operation.
	 */
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H eap_status_e decode(const eap_variable_data_c * const asn1_der_data);

	/**
	 * The get_class() returns Class of ASN.1/DER type.
	 */
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H asn1_class_e get_class() const;

	/**
	 * The get_pc() returns Primitiva/Constructed flag of ASN.1/DER type.
	 */
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H asn1_pc_e get_pc() const;

	/**
	 * The get_pc() returns Tag of ASN.1/DER type.
	 */
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H asn1_tag_e get_tag() const;

	/**
	 * The get_pc() returns pointer to extented Tag of ASN.1/DER type.
	 */
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H eap_status_e get_extented_tag(const u8_t ** const extented_tag, u32_t * const extented_tag_size) const;

	// Function returns count of octets in header of ASN.1/DER type.
	// This includes Identifier and Length octets.
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H u32_t get_header_length() const;


	// Function returns count of octets in Contents of ASN.1/DER type.
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H u32_t get_content_length() const;

	// Function returns pointer to Contents of ASN.1/DER type.
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H const u8_t * get_content() const;


	// Function returns count of octets in full data of ASN.1/DER type, including Identifier, Length and Content.
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H u32_t get_full_data_length() const;

	// Function returns pointer to full data of ASN.1/DER type, including Identifier, Length and Content.
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H const u8_t * get_full_data() const;


	// Function returns pointer to array of ASN.1/DER sub types.
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H const eap_array_c<asn1_der_type_c> * get_sub_types() const;

	// Function returns pointer to ASN.1/DER sub type.
	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H const asn1_der_type_c * get_sub_type(const asn1_type_const_c * const asn1_type) const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H const asn1_der_type_c * get_previous_type() const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H const asn1_der_type_c * get_next_type() const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H u16_t get_count_of_sub_types() const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H void increase_count_of_sub_types();

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H eap_const_string get_class_string() const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H eap_const_string get_pc_string() const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H eap_const_string get_tag_string() const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H eap_status_e compare_object_identifier(const u8_t * const der_encoded_oid, const u32_t oid_length) const;

	EAP_FUNC_VISIBILITY_ASN1_DER_TYPE_H eap_status_e compare_object_identifier(eap_const_string oid, const u32_t oid_length) const;

	//--------------------------------------------------
private:
	//--------------------------------------------------

	abs_eap_am_tools_c * const m_am_tools;

	bool m_is_valid;

	u16_t m_index;

	u16_t m_count_of_sub_types;

	// Shows the recursion of ANS.1 type. The outer most have value 0.
	u16_t m_recursion;

	// +--------------+--------------+--------------+
	// | Identifier   | Length       | Content      |
	// +--------------+--------------+--------------+
	// 
	// +--------------------------------------------+
	//          m_input_data_length in octets
	u32_t m_input_data_length;

	// +--------------+--------------+--------------+
	// | Identifier   | Length       | Content      |
	// +--------------+--------------+--------------+
	// ^
	// |
	// This is pointer to begin of the input data.
	const u8_t * m_input_data;

	// Tells how many octets of tha data is used by sub types.
	u32_t m_used_octets;

	// +--------------+--------------+--------------+
	// | Identifier   | Length       | Content      |
	// +--------------+--------------+--------------+
	// 
	// +--------------+
	//     offset
	u16_t m_offset_of_length_field;

	// +--------------+--------------+--------------+
	// | Identifier   | Length       | Content      |
	// +--------------+--------------+--------------+
	// 
	// +-----------------------------+
	//             offset
	u16_t m_offset_of_contents_field;

	// This is pointer to parent type.
	asn1_der_type_c * m_parent_type;

	// This array includes all sub types.
	eap_array_c<asn1_der_type_c> * m_sub_types;

	//--------------------------------------------------

#if defined(USE_EAP_DEBUG_TRACE)

	enum asn1_debug_const_e
	{
		MAX_DEBUG_BUFFER = 256,
		MAX_STACK_BUFFER = 64,
		SIZE_OF_ONE_OCTET_STRING = 3ul,
		COUNT_OF_OCTETS = 16ul,
		OID_HIGH_BIT = 0x80,
	};

	eap_status_e debug_create_prefix(const u32_t recursion, u8_t * const prefix, const u32_t max_prefix, u32_t * const pregix_length);

	eap_status_e debug_header(eap_variable_data_c * const debug_buffer);

	eap_status_e debug_content(eap_variable_data_c * const debug_buffer);

	eap_status_e debug_data(eap_variable_data_c * const debug_buffer);

	eap_status_e debug_object_identifier(eap_variable_data_c * const debug_buffer);

#endif //#if defined(USE_EAP_DEBUG_TRACE)

	eap_status_e add_sub_type(asn1_der_type_c * const sub_type);

	eap_status_e initialize(
		const u32_t length,
		const u8_t * const data,
		const u16_t recursion,
		const u32_t index,
		eap_variable_data_c * const debug_buffer);

	u16_t get_offset_of_length_field();

	u16_t get_offset_of_contents_field();

	void set_parent_type(asn1_der_type_c * const parent_type);

	asn1_der_type_c * get_parent_type() const;

	u32_t get_input_data_length() const;

	const u8_t * get_input_data() const;

	u16_t get_recursion() const;

	void add_used_octets(const u32_t used_octets);

	u32_t get_used_octets() const;

	u32_t get_unused_data_length() const;

	const u8_t * get_unused_data() const;

	eap_status_e encode_oid_from_string(eap_const_string oid, const u32_t oid_length, eap_variable_data_c * const buffer) const;

	//--------------------------------------------------
};

//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------

class asn1_type_object_c
{
public:

	~asn1_type_object_c()
	{
	}

	asn1_der_type_c::asn1_class_e get_asn1_class() const
	{
		return m_asn1_class;
	}

	asn1_der_type_c::asn1_tag_e get_asn1_tag() const
	{
		return m_asn1_tag;
	}

	u32_t get_index() const
	{
		return m_index;
	}

	bool get_is_valid() const
	{
		return(
			get_asn1_class() != asn1_der_type_c::asn1_class_none
			&& get_asn1_tag() != asn1_der_type_c::asn1_tag_none);
	}

	bool compare(
		abs_eap_am_tools_c * const /* tools */,
		const asn1_type_object_c * const field) const
	{
		return field->get_asn1_class() == get_asn1_class()
			&& field->get_asn1_tag() == get_asn1_tag();
	}

private:
	asn1_der_type_c::asn1_class_e m_asn1_class;
	asn1_der_type_c::asn1_tag_e m_asn1_tag;
	u32_t m_index;
};

//--------------------------------------------------------------------------------------------------

class asn1_type_const_c
{
public:

	inline const asn1_type_object_c * get_type() const;

	inline bool get_is_valid() const
	{
		return true;
	}


public:
	asn1_der_type_c::asn1_class_e m_asn1_class;
	asn1_der_type_c::asn1_tag_e m_asn1_tag;
	u32_t m_index;
};

//--------------------------------------------------------------------------------------------------

inline const asn1_type_object_c * asn1_type_const_c::get_type() const
{
	EAP_STATIC_ASSERT(sizeof(asn1_type_const_c) == sizeof(asn1_type_object_c));

	return reinterpret_cast<const asn1_type_object_c *>(this);
}

//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------

template <u32_t max_name_length, u32_t max_object_count>
class asn1_named_object_const_c
{
public:

	inline const eap_char * get_name() const;

	inline const asn1_type_const_c * get_array() const;

	inline bool get_is_valid() const
	{
		return true;
	}

public:

	eap_char m_name[max_name_length];
	asn1_type_const_c m_array[max_object_count];

};

//--------------------------------------------------------------------------------------------------

template <u32_t max_name_length, u32_t max_object_count>
inline const eap_char * asn1_named_object_const_c<max_name_length, max_object_count>::get_name() const
{
	return m_name;
}

template <u32_t max_name_length, u32_t max_object_count>
inline const asn1_type_const_c * asn1_named_object_const_c<max_name_length, max_object_count>::get_array() const
{
	return m_array;
}

//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------

#define ASN1_TYPE_OBJECT(asn1_class, asn1_tag, index) \
	{asn1_class, static_cast<asn1_der_type_c::asn1_tag_e>(asn1_tag), index}

#define ASN1_TYPE_OBJECT_TERMINATOR \
	{asn1_der_type_c::asn1_class_none, asn1_der_type_c::asn1_tag_none, 0ul}

//--------------------------------------------------------------------------------------------------

#if defined(USE_EAP_DEBUG_TRACE)
	#define ASN1_DEBUG_HEADER(type, debug_buffer) { (void) (type)->debug_header(debug_buffer); }
	#define ASN1_DEBUG_DATA(type, debug_buffer) { (void) (type)->debug_content(debug_buffer); }
#else
	#define ASN1_DEBUG_HEADER(type, debug_buffer)
	#define ASN1_DEBUG_DATA(type, debug_buffer)
#endif //#if defined(USE_EAP_DEBUG_TRACE)

#if defined(USE_ASN1_TYPE_DEBUG_TRACE)
	#define ASN1_TYPE_TRACE_DEBUG EAP_TRACE_DEBUG
	#define ASN1_TYPE_TRACE_DATA_DEBUG EAP_TRACE_DATA_DEBUG
#else
	#define ASN1_TYPE_TRACE_DEBUG(object_name, flags, _parameter_list_)
	#define ASN1_TYPE_TRACE_DATA_DEBUG(object_name, flags, _parameter_list_)
#endif

#endif //#if !defined(_ASN1_TYPE_H_)

//--------------------------------------------------------------------------------------------------

// End.
