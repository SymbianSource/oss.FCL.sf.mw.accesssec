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
* %version: 18 %
*/

#ifndef _FILECONFIG_H
#define _FILECONFIG_H

#include "eap_core_map.h"
#include "eap_configuration_field.h"
#include "abs_eap_am_file_input.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAP_FILE_CONFIG_H)
	#define EAP_CLASS_VISIBILITY_EAP_FILE_CONFIG_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H 
	#define EAP_C_FUNC_VISIBILITY_EAP_FILE_CONFIG_H 
	#define EAP_FUNC_EXPORT_EAP_FILE_CONFIG_H 
	#define EAP_C_FUNC_EXPORT_EAP_FILE_CONFIG_H 
#elif defined(EAP_EXPORT_EAP_FILE_CONFIG_H)
	#define EAP_CLASS_VISIBILITY_EAP_FILE_CONFIG_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_FILE_CONFIG_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAP_FILE_CONFIG_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAP_FILE_CONFIG_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAP_FILE_CONFIG_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAP_FILE_CONFIG_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAP_FILE_CONFIG_H 
	#define EAP_C_FUNC_EXPORT_EAP_FILE_CONFIG_H 
#endif
// End: added by script change_export_macros.sh.


class eap_tlv_header_c;


template <class Type>
Type minimum( Type a, Type b )
{
	return a < b ? a : b;
}


class EAP_CLASS_VISIBILITY_EAP_FILE_CONFIG_H eap_config_value_c
{
private:

	abs_eap_am_tools_c* const m_am_tools;

	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * m_subsection_map;

	eap_variable_data_c m_data;

	eap_configure_type_e m_type;

	bool m_is_valid;

public:

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H virtual ~eap_config_value_c();

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_config_value_c(
		abs_eap_am_tools_c* const tools);

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H void set_subsection(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const subsection_map);

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * get_subsection();

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_variable_data_c * get_data();

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H const eap_variable_data_c * get_const_data() const;

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H void set_type(const eap_configure_type_e type);

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_configure_type_e get_type();

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_configure_type_e get_const_type() const;

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H void object_increase_reference_count();

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H bool get_is_valid() const;

};

const u32_t MAX_LINE_LENGTH = 1024;
const u32_t MAX_CONFIG_TYPE_LENGTH = 32;


struct eap_configure_type
{
	char id[MAX_CONFIG_TYPE_LENGTH];
	u32_t id_length;
	eap_configure_type_e type;
};


const char * const EAP_FILECONFIG_TRUE = "true";
const char * const EAP_FILECONFIG_FALSE = "false";


const char EAP_FILECONFIG_SECTION[] = "section:";
const u32_t EAP_FILECONFIG_SECTION_LENGTH = (sizeof(EAP_FILECONFIG_SECTION)-1ul);

const char EAP_FILECONFIG_SECTION_START[] = "{";
const u32_t EAP_FILECONFIG_SECTION_START_LENGTH = (sizeof(EAP_FILECONFIG_SECTION_START)-1ul);

const char EAP_FILECONFIG_SECTION_END[] = "}";
const u32_t EAP_FILECONFIG_SECTION_END_LENGTH = (sizeof(EAP_FILECONFIG_SECTION_END)-1ul);


/// Keep this on the same order as eap_configure_type_e.
const eap_configure_type eap_configure_type_id[] =
{
	{
		"none:", 
		5u, 
		eap_configure_type_none
	},
	{
		"u32_t:", 
		6u, 
		eap_configure_type_u32_t
	},
	{
		"bool:", 
		5u, 
		eap_configure_type_boolean
	},
	{
		"string:", 
		7u, 
		eap_configure_type_string
	},
	{
		"hex:", 
		4u, 
		eap_configure_type_hex_data
	},
	{
		"u32array:", 
		9u, 
		eap_configure_type_u32array
	},
};


class EAP_CLASS_VISIBILITY_EAP_FILE_CONFIG_H eap_file_config_c
: public abs_eap_core_map_c
{
  
 private:

	abs_eap_am_tools_c* const m_am_tools;

	/// This stores eap_config_value_c objects using eap_variable_data selector.
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> m_config_map;

	eap_variable_data_c m_value_buffer;

	bool m_is_valid;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	eap_status_e expand_environment_variables(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const eap_variable_data_c * const value,
		eap_variable_data_c * const expanded_value
		);

	eap_status_e remove_spaces(eap_variable_data_c * const buffer);

	eap_status_e remove_leading_spaces(eap_variable_data_c * const line);

	eap_status_e read_section(
		abs_eap_am_file_input_c * const file,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map);

	eap_status_e read_subsections(
		abs_eap_am_file_input_c * const file,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map);

	eap_status_e get_subsect(
		abs_eap_am_file_input_c * const file,
		eap_variable_data_c * const line);

	eap_status_e convert_value(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const eap_variable_data_c * const value_buffer,
		const eap_configure_type_e type,
		eap_variable_data_c * const value_data);

	eap_status_e store_configure(
		abs_eap_am_file_input_c * const file,
		const eap_variable_data_c * const line,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map);

	eap_status_e cnf_parse_value(
		const eap_variable_data_c * const found_type_value,
		const eap_variable_data_c * const found_type_name,
		eap_configure_type_e * const parsed_type,
		eap_variable_data_c * const parsed_type_value,
		const bool is_environment_variable);

	eap_status_e cnf_get_string(
		const eap_variable_data_c * const param,
		eap_variable_data_c * const param_name,
		eap_variable_data_c * const param_value,
		eap_configure_type_e * const type);

	eap_status_e find_rvalue(
		const eap_variable_data_c * const config_param,
		bool * const read_env_value,
		eap_variable_data_c * const param_name,
		eap_variable_data_c * const param_value
		);

	u8_t * read_hex_byte(
		u8_t * cursor,
		const u8_t * const end,
		u8_t * const hex_byte,
		const u32_t hex_byte_length);

	u8_t * read_u32_t(u8_t * cursor, const u8_t * const end, u32_t * const hex_byte);

	eap_status_e read_configure(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const eap_configuration_field_c * const field,
		eap_variable_data_c* const data,
		eap_configure_type_e * const configuration_data_type,
		const bool existence_test);

	eap_status_e file_read_line(
		abs_eap_am_file_input_c * const file,
		eap_variable_data_c * const line);

	eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c* const data,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const bool check_subsection_when_true);

	eap_status_e read_all_configurations(
		const eap_configuration_field_c * const field,
		eap_variable_data_c* const data,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map);

	eap_status_e add_option(
		const eap_tlv_header_c * const option_header);

 public:

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_file_config_c(
		abs_eap_am_tools_c* const tools);

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H virtual ~eap_file_config_c();

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_status_e configure(
		abs_eap_am_file_input_c * const file);

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_status_e read_configuration_message(
		const eap_variable_data_c * const configuration_message);

	EAP_FUNC_VISIBILITY_EAP_FILE_CONFIG_H eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c* const data);

	bool get_is_valid() const
	{
		return m_is_valid;
	}

	void set_is_valid()
	{
		m_is_valid = true;
	}
};

#endif /* #ifndef _FILECONFIG_H */

