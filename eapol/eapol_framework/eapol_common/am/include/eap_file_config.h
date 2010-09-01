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
* %version: 11.1.2 %
*/

#ifndef _FILECONFIG_H
#define _FILECONFIG_H

#include "eap_core_map.h"
#include "eap_configuration_field.h"
#include "abs_eap_am_file_input.h"


template <class Type>
Type minimum( Type a, Type b )
{
	return a < b ? a : b;
}


class eap_config_value_c
{
private:

	abs_eap_am_tools_c* const m_am_tools;

	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * m_subsection_map;

	eap_variable_data_c m_data;

	eap_configure_type_e m_type;

	bool m_is_valid;

public:

	virtual ~eap_config_value_c();

	eap_config_value_c(
		abs_eap_am_tools_c* const tools);

	void set_subsection(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const subsection_map);

	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * get_subsection();

	eap_variable_data_c * get_data();

	void set_type(const eap_configure_type_e type);

	eap_configure_type_e get_type();

	void object_increase_reference_count();

	bool get_is_valid();

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


class EAP_EXPORT eap_file_config_c
: public abs_eap_core_map_c
{
  
 private:
	abs_eap_am_tools_c* const m_am_tools;

	/// This stores eap_config_value_c objects using eap_variable_data selector.
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> m_config_map;

	bool m_is_valid;

	EAP_FUNC_IMPORT eap_status_e expand_environment_variables(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const eap_variable_data_c * const value,
		eap_variable_data_c * const expanded_value
		);

	EAP_FUNC_IMPORT eap_status_e remove_spaces(eap_variable_data_c * const buffer);

	EAP_FUNC_IMPORT eap_status_e remove_leading_spaces(eap_variable_data_c * const line);

	EAP_FUNC_IMPORT eap_status_e read_section(
		abs_eap_am_file_input_c * const file,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map);

	EAP_FUNC_IMPORT eap_status_e  read_subsections(
		abs_eap_am_file_input_c * const file,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map);

	EAP_FUNC_IMPORT eap_status_e get_subsect(
		abs_eap_am_file_input_c * const file,
		eap_variable_data_c * const line);

	EAP_FUNC_IMPORT eap_status_e convert_value(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const eap_variable_data_c * const value_buffer,
		const eap_configure_type_e type,
		eap_variable_data_c * const value_data);

	EAP_FUNC_IMPORT eap_status_e store_configure(
		abs_eap_am_file_input_c * const file,
		const eap_variable_data_c * const line,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map);

	EAP_FUNC_IMPORT eap_status_e cnf_parse_value(
		const eap_variable_data_c * const found_type_value,
		const eap_variable_data_c * const found_type_name,
		eap_configure_type_e * const parsed_type,
		eap_variable_data_c * const parsed_type_value,
		const bool is_environment_variable);

	EAP_FUNC_IMPORT eap_status_e cnf_get_string(
		const eap_variable_data_c * const param,
		eap_variable_data_c * const param_name,
		eap_variable_data_c * const param_value,
		eap_configure_type_e * const type);

	EAP_FUNC_IMPORT eap_status_e find_rvalue(
		const eap_variable_data_c * const config_param,
		bool * const read_env_value,
		eap_variable_data_c * const param_name,
		eap_variable_data_c * const param_value
		);

	EAP_FUNC_IMPORT u8_t * read_hex_byte(u8_t * cursor, const u8_t * const end, u8_t * const hex_byte);

	EAP_FUNC_IMPORT u8_t * read_u32_t(u8_t * cursor, const u8_t * const end, u32_t * const hex_byte);

	EAP_FUNC_IMPORT eap_status_e read_configure(
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const eap_configuration_field_c * const field,
		eap_variable_data_c* const data,
		eap_configure_type_e * const configuration_data_type,
		const bool existence_test);

	EAP_FUNC_IMPORT eap_status_e file_read_line(
		abs_eap_am_file_input_c * const file,
		eap_variable_data_c * const line);

	EAP_FUNC_IMPORT eap_status_e read_configure(
		const eap_configuration_field_c * const field,
		eap_variable_data_c* const data,
		eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
		const bool check_subsection_when_true);

 public:

	EAP_FUNC_IMPORT eap_file_config_c(
		abs_eap_am_tools_c* const tools);

	EAP_FUNC_IMPORT virtual ~eap_file_config_c();

	EAP_FUNC_IMPORT eap_status_e configure(
		abs_eap_am_file_input_c * const file);

	EAP_FUNC_IMPORT eap_status_e read_configure(
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

