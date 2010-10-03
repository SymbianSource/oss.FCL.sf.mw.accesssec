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
* %version: 35 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 14 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_file_config.h"
#include "eap_automatic_variable.h"
#include "eap_tlv_message_data.h"
#include "eap_process_tlv_message_data.h"
#include "eap_config.h"

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif


#if 0
	const u32_t TRACE_FLAGS_CONFIGURE_DATA = TRACE_FLAGS_DEFAULT;
#else
	const u32_t TRACE_FLAGS_CONFIGURE_DATA = eap_am_tools_c::eap_trace_mask_none;
#endif

//-----------------------------------------------------------------
//-----------------------------------------------------------------
//-----------------------------------------------------------------

EAP_FUNC_EXPORT eap_config_value_c::~eap_config_value_c()
{
	delete m_subsection_map;
	m_subsection_map = 0;
}

EAP_FUNC_EXPORT eap_config_value_c::eap_config_value_c(
	abs_eap_am_tools_c* const tools)
	: m_am_tools(tools)
	, m_subsection_map(0)
	, m_data(tools)
	, m_type(eap_configure_type_none)
	, m_is_valid(false)
{
	EAP_ASSERT(eap_configure_type_id[eap_configure_type_none].type == eap_configure_type_none);	
	EAP_ASSERT(eap_configure_type_id[eap_configure_type_u32_t].type == eap_configure_type_u32_t);	
	EAP_ASSERT(eap_configure_type_id[eap_configure_type_boolean].type == eap_configure_type_boolean);	
	EAP_ASSERT(eap_configure_type_id[eap_configure_type_string].type == eap_configure_type_string);	
	EAP_ASSERT(eap_configure_type_id[eap_configure_type_hex_data].type == eap_configure_type_hex_data);	
	EAP_ASSERT(eap_configure_type_id[eap_configure_type_u32array].type == eap_configure_type_u32array);	

	if (m_data.get_is_valid() == false)
	{
		return;
	}

	m_is_valid = true;
}

EAP_FUNC_EXPORT void eap_config_value_c::set_subsection(
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const subsection_map)
{
	m_subsection_map = subsection_map;
}

EAP_FUNC_EXPORT eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * eap_config_value_c::get_subsection()
{
	return m_subsection_map;
}

EAP_FUNC_EXPORT eap_variable_data_c * eap_config_value_c::get_data()
{
	return &m_data;
}

EAP_FUNC_EXPORT const eap_variable_data_c * eap_config_value_c::get_const_data() const
{
	return &m_data;
}

EAP_FUNC_EXPORT void eap_config_value_c::set_type(const eap_configure_type_e type)
{
	m_type = type;
}

EAP_FUNC_EXPORT eap_configure_type_e eap_config_value_c::get_type()
{
	return m_type;
}

EAP_FUNC_EXPORT eap_configure_type_e eap_config_value_c::get_const_type() const
{
	return m_type;
}

EAP_FUNC_EXPORT void eap_config_value_c::object_increase_reference_count()
{
}

EAP_FUNC_EXPORT bool eap_config_value_c::get_is_valid() const
{
	return m_is_valid;
}

//-----------------------------------------------------------------
//-----------------------------------------------------------------
//-----------------------------------------------------------------


EAP_FUNC_EXPORT eap_file_config_c::eap_file_config_c(
	abs_eap_am_tools_c* const tools)
  : m_am_tools(tools)
  , m_config_map(tools, this)
  , m_value_buffer(tools)
  , m_is_valid(false)
{
	EAP_UNREFERENCED_PARAMETER(TRACE_FLAGS_CONFIGURE_DATA); // in release
	
	set_is_valid();
}

//-----------------------------------------------------------------

EAP_FUNC_EXPORT eap_file_config_c::~eap_file_config_c()
{
}

//-----------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_file_config_c::configure(
	abs_eap_am_file_input_c * const file)
{
	eap_status_e status = read_subsections(file, &m_config_map);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::expand_environment_variables(
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
	const eap_variable_data_c * const original_value,
	eap_variable_data_c * const expanded_value
	)
{
	eap_status_e status = eap_status_process_general_error;

	if (original_value == 0
		|| expanded_value == 0
		)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u8_t env_char = '$';
	const u8_t char_left_parenthesis = '(';
	const u8_t char_right_parenthesis = ')';
	bool expanded_value_when_true = false;

	if (m_value_buffer.get_buffer_length() < MAX_LINE_LENGTH)
	{
		status = m_value_buffer.set_buffer_length(MAX_LINE_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = expanded_value->set_copy_of_buffer(original_value);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (;;)
	{
		u8_t * const start_of_value = expanded_value->get_data(expanded_value->get_data_length());

		u8_t * const env_start = static_cast<u8_t *>(m_am_tools->memchr(
			start_of_value,
			env_char,
			expanded_value->get_data_length()));

		if (env_start == 0)
		{
			status = eap_status_ok;
			break;
		}
		else
		{
			if (static_cast<u32_t>((env_start+2)-start_of_value) < expanded_value->get_data_length()
				&& env_start[1] == char_left_parenthesis)
			{
				u8_t *tmp_end = start_of_value + expanded_value->get_data_length();

				u8_t *env_end = static_cast<u8_t *>(m_am_tools->memchr(
					env_start,
					char_right_parenthesis,
					tmp_end-env_start));
				if (env_end != 0)
				{
					*env_end = '\0';

					u8_t *env_name = env_start+2;

					eap_variable_data_c env_name_buffer(m_am_tools);
					if (env_name_buffer.get_is_valid() == false)
					{
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = env_name_buffer.set_buffer(
						env_name,
						env_end-env_name,
						false,
						false);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}

					eap_variable_data_c env_value_buffer(m_am_tools);
					if (env_value_buffer.get_is_valid() == false)
					{
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					eap_status_e env_status = m_am_tools->getenv(
						&env_name_buffer,
						&env_value_buffer);

					eap_variable_data_c parsed_value_buffer(m_am_tools);
					if (parsed_value_buffer.get_is_valid() == false)
					{
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					status = parsed_value_buffer.set_buffer_length(MAX_LINE_LENGTH);
					if (status != eap_status_ok)
					{
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
					parsed_value_buffer.set_data_length(MAX_LINE_LENGTH);

					eap_variable_data_c configure_option(m_am_tools);
					if (configure_option.get_is_valid() == false)
					{
						return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
					}

					if (env_status != eap_status_ok)
					{
						// Next check whether a one of the defined configuration
						// options match to the variable.
						eap_configure_type_e configuration_data_type = eap_configure_type_none;
						static const u32_t EAP_MAX_CONFIG_BUFFER_LENGTH = 256;
						eap_configuration_field_template_c<EAP_MAX_CONFIG_BUFFER_LENGTH> * const tmp_env_name
							= new eap_configuration_field_template_c<EAP_MAX_CONFIG_BUFFER_LENGTH>;

						eap_automatic_variable_c<eap_configuration_field_template_c<EAP_MAX_CONFIG_BUFFER_LENGTH> >
							automatic_tmp_env_name(m_am_tools, tmp_env_name);

						if (tmp_env_name == 0)
						{
							return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
						}

						eap_status_e status = tmp_env_name->set_fields(
							m_am_tools,
							env_name,
							eap_configure_type_none,
							false);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}

						status = read_configure(
							config_map,
							tmp_env_name->get_field(),
							&configure_option,
							&configuration_data_type,
							false);

						if (status == eap_status_ok)
						{
							if (configuration_data_type == eap_configure_type_string)
							{
								status = configure_option.add_end_null();
							}
							else if (configuration_data_type == eap_configure_type_u32_t)
							{
								u32_t * const p_value = reinterpret_cast<u32_t *>(
									configure_option.get_data(
										configure_option.get_data_length()));
								if (p_value != 0)
								{
									u32_t value = *p_value;

									status = configure_option.set_buffer_length(EAP_MAX_CONFIG_BUFFER_LENGTH);
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}

									status = configure_option.set_data_length(EAP_MAX_CONFIG_BUFFER_LENGTH);
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}

									u32_t length = m_am_tools->snprintf(
											reinterpret_cast<u8_t *>(
												configure_option.get_data(
													configure_option.get_data_length())),
											EAP_MAX_CONFIG_BUFFER_LENGTH,
											EAPL("%u"),
											value);
									status = configure_option.set_data_length(length);
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}

									status = configure_option.add_end_null();
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}
								}
							}
							else if (configuration_data_type == eap_configure_type_boolean)
							{
								u32_t * const p_value = reinterpret_cast<u32_t *>(
									configure_option.get_data(
										configure_option.get_data_length()));
								if (p_value != 0)
								{
									bool value = (*p_value == 0) ? false : true;

									status = configure_option.set_buffer_length(EAP_MAX_CONFIG_BUFFER_LENGTH);
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}

									status = configure_option.set_data_length(EAP_MAX_CONFIG_BUFFER_LENGTH);
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}

									if (value == true)
									{
										u32_t length = m_am_tools->snprintf(
												reinterpret_cast<u8_t *>(
													configure_option.get_data(
														configure_option.get_data_length())),
												EAP_MAX_CONFIG_BUFFER_LENGTH,
												EAPL("true"));
										status = configure_option.set_data_length(length);
										if (status != eap_status_ok)
										{
											EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
											return EAP_STATUS_RETURN(m_am_tools, status);
										}
									}
									else
									{
										u32_t length = m_am_tools->snprintf(
												reinterpret_cast<u8_t *>(
													configure_option.get_data(
														configure_option.get_data_length())),
												EAP_MAX_CONFIG_BUFFER_LENGTH,
												EAPL("false"));
										configure_option.set_data_length(length);
									}

									status = configure_option.add_end_null();
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}
								}
							}
							else if (configuration_data_type == eap_configure_type_hex_data)
							{
								u8_t * const p_value = reinterpret_cast<u8_t *>(
									configure_option.get_data(
										configure_option.get_data_length()));

								u8_t buffer[3];
								u8_t comma(',');

								eap_variable_data_c tmp(m_am_tools);
								if (tmp.get_is_valid() == false)
								{
									return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
								}

								for (u32_t ind = 0ul; ind < configure_option.get_data_length(); ind++)
								{
									u32_t length = m_am_tools->snprintf(
											buffer,
											sizeof(buffer),
											EAPL("%02x"),
											p_value[ind]);

									status = tmp.add_data(buffer, length);
									if (status != eap_status_ok)
									{
										EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
										return EAP_STATUS_RETURN(m_am_tools, status);
									}

									if ((ind+1) < configure_option.get_data_length())
									{
										status = tmp.add_data(&comma, sizeof(comma));
										if (status != eap_status_ok)
										{
											EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
											return EAP_STATUS_RETURN(m_am_tools, status);
										}
									}
								} // for()

								status = configure_option.set_copy_of_buffer(&tmp);
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}

								status = configure_option.add_end_null();
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}
							}
						}

						if (configure_option.get_is_valid_data() == false
							|| configure_option.get_data_length() == 0ul)
						{
							#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
								printf("WARNING: CONFIG: unknown environment variable %s.\n",
									   env_name);
							#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

							EAP_TRACE_DEBUG(
								m_am_tools,
								TRACE_FLAGS_DEFAULT,
								(EAPL("WARNING: CONFIG: unknown environment variable %s.\n"),
								 env_name));

							// This is empty environment value.
						}
					}
					else
					{
						// OK environment variable found.
						eap_configure_type_e type = eap_configure_type_none;

						status = cnf_parse_value(
							&env_value_buffer,
							&env_name_buffer,
							&type,
							&configure_option,
							true
							);
						if (status != eap_status_ok)
						{
							EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
							return EAP_STATUS_RETURN(m_am_tools, status);
						}
					}


					if (configure_option.get_is_valid_data() == true
						&& configure_option.get_data_length() > 0ul)
					{
						m_value_buffer.reset_start_offset_and_data_length();

						u32_t tmp_index = 0ul;

						if (env_start > start_of_value)
						{
							u32_t length_of_begin = env_start-start_of_value;
							if (length_of_begin > 0ul)
							{
								status = m_value_buffer.set_copy_of_buffer(
									expanded_value->get_data(length_of_begin),
									length_of_begin);
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}

								tmp_index += length_of_begin;
							}
						}

						if (configure_option.get_data_length() > 0ul)
						{
							status = m_value_buffer.add_data(&configure_option);
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}

							tmp_index += configure_option.get_data_length();
						}

						if (tmp_end > (env_end+1))
						{
							u32_t length_of_end = tmp_end-(env_end+1);
							if (length_of_end > 0ul)
							{
								status = m_value_buffer.add_data(
									(env_end+1),
									length_of_end);
								if (status != eap_status_ok)
								{
									EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
									return EAP_STATUS_RETURN(m_am_tools, status);
								}

								tmp_index += length_of_end;
							}
						}

						if (m_value_buffer.get_is_valid_data() == true
							&& m_value_buffer.get_data_length() > 0ul)
						{
							status = expanded_value->set_copy_of_buffer(&m_value_buffer);
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}

							status = expanded_value->add_end_null();
							if (status != eap_status_ok)
							{
								EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
								return EAP_STATUS_RETURN(m_am_tools, status);
							}

							expanded_value_when_true = true;
						}

					}
				}
				else
				{
					#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
						printf("ERROR: CONFIG: illegal configure value %s.\n",
							   expanded_value->get_data(expanded_value->get_data_length()));
					#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

					EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
									(EAPL("ERROR: CONFIG: illegal configure value %s.\n"),
									 expanded_value->get_data(expanded_value->get_data_length())));
					status = eap_status_illegal_configure_field;
					break;
				}
			}
			else
			{
				#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
					printf("ERROR: CONFIG: illegal configure value %s.\n",
						   expanded_value->get_data(expanded_value->get_data_length()));
				#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
								(EAPL("ERROR: CONFIG: illegal configure value %s.\n"),
								 expanded_value->get_data(expanded_value->get_data_length())));
				status = eap_status_illegal_configure_field;
				break;
			}
		}
	} // for()

	if (status == eap_status_ok
		&& expanded_value_when_true == true)
	{
		#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
			printf("CONFIG: expanded configuration value [%s] => [%s].\n",
				value,
				expanded_value);
		#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
						(EAPL("CONFIG: expanded configuration value [%s] => [%s].\n"),
						 original_value->get_data(original_value->get_data_length()),
						 expanded_value->get_data(expanded_value->get_data_length())));
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

u8_t * eap_file_config_c::read_hex_byte(
	u8_t * cursor,
	const u8_t * const end,
	u8_t * const hex_byte, // This buffer is one byte in length.
	const u32_t hex_byte_length)
{
	u8_t * start = cursor;
	bool stop = false;

	while(stop == false && cursor < end)
	{
		switch(*cursor)
		{
		case static_cast<u8_t>(','):
		case static_cast<u8_t>(' '):
		case static_cast<u8_t>('\t'):
			stop = true;
			break;
		default:
			++cursor;
			break;
		}

	}

	if (cursor <= end)
	{
		u32_t target_length = hex_byte_length;

		eap_status_e status = m_am_tools->convert_hex_ascii_to_bytes(
			start,
			cursor-start,
			hex_byte,
			&target_length);
		if (status != eap_status_ok
			|| target_length != hex_byte_length)
		{
			return 0;
		}

		return ++cursor;
	}

	return 0;
}

//-----------------------------------------------------------------

u8_t * eap_file_config_c::read_u32_t(
	u8_t * cursor,
	const u8_t * const end,
	u32_t * const integer)
{
	u8_t * start = cursor;
	bool stop = false;

	while(stop == false && cursor < end)
	{
		switch(*cursor)
		{
		case static_cast<u8_t>(','):
		case static_cast<u8_t>(' '):
		case static_cast<u8_t>('\t'):
			stop = true;
			break;
		default:
			++cursor;
			break;
		}

	}

	if (cursor <= end)
	{
		eap_variable_data_c buffer(m_am_tools);
		if (buffer.get_is_valid() == false)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			return 0;
		}

		eap_status_e status = buffer.add_data(start, cursor-start);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}

		status = m_am_tools->number_string_to_u32(
			buffer.get_data(buffer.get_data_length()),
			buffer.get_data_length(),
			integer);
		if (status != eap_status_ok)
		{
			(void) EAP_STATUS_RETURN(m_am_tools, status);
			return 0;
		}

		return ++cursor;
	}

	(void) EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_data_payload);
	return 0;
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::convert_value(
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
	const eap_variable_data_c * const value_buffer,
	const eap_configure_type_e type,
	eap_variable_data_c * const value_data)
{
	eap_status_e status = eap_status_process_general_error;

		eap_variable_data_c expanded_value_buffer(m_am_tools);
		if (expanded_value_buffer.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = expanded_value_buffer.set_buffer_length(MAX_LINE_LENGTH);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		expanded_value_buffer.set_data_length(MAX_LINE_LENGTH);

		status = expand_environment_variables(
			config_map,
			value_buffer,
			&expanded_value_buffer);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		if (type == eap_configure_type_u32_t)
		{
			u32_t uint_value = 0UL;
			
			status = m_am_tools->number_string_to_u32(
				expanded_value_buffer.get_data(expanded_value_buffer.get_data_length()),
				expanded_value_buffer.get_data_length(),
				&uint_value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = value_data->set_copy_of_buffer(
				&uint_value,
				sizeof(uint_value));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (type == eap_configure_type_boolean)
		{
			u32_t uint_value = static_cast<u32_t>(~0);
			
			if (!m_am_tools->memcmp(
					expanded_value_buffer.get_data(expanded_value_buffer.get_data_length()),
					EAP_FILECONFIG_TRUE,
					expanded_value_buffer.get_data_length()))
			{
				// OK, true
				uint_value = 1u;
			}
			else if (!m_am_tools->memcmp(
						 expanded_value_buffer.get_data(expanded_value_buffer.get_data_length()),
						 EAP_FILECONFIG_FALSE,
						 expanded_value_buffer.get_data_length()))
			{
				// OK, false
				uint_value = 0u;
			}
			else
			{
#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
				printf("ERROR: CONFIG: illegal boolean value %s\n",
					   expanded_value_buffer.get_data(expanded_value_buffer.get_data_length()));
#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
				
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
								(EAPL("ERROR: CONFIG: illegal boolean value %s\n"),
								 expanded_value_buffer.get_data(expanded_value_buffer.get_data_length())));
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
			}
			
			status = value_data->set_copy_of_buffer(
				&uint_value,
				sizeof(uint_value));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (type == eap_configure_type_string)
		{
			status = value_data->set_copy_of_buffer(
				&expanded_value_buffer);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (type == eap_configure_type_hex_data)
		{
			status = remove_spaces(&expanded_value_buffer);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = value_data->set_buffer_length((expanded_value_buffer.get_data_length()+1)/3);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = value_data->set_data_length(value_data->get_buffer_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u8_t * const target = value_data->get_data(value_data->get_buffer_length());
			if (target == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			u32_t ind_target(0ul);

			u8_t * cursor = expanded_value_buffer.get_data(expanded_value_buffer.get_data_length());
			if (cursor == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			const u8_t * const cursor_end = cursor + expanded_value_buffer.get_data_length();

			// Only one byte is needed. This is because coverity complains of using "u8_t hex_byte".
			const u32_t BUFFER_SIZE=1ul;
			u8_t hex_byte[BUFFER_SIZE];

			while(cursor < cursor_end)
			{
				cursor = read_hex_byte(
					cursor,
					cursor_end,
					hex_byte,
					BUFFER_SIZE);
				if (cursor == 0)
				{
					break;
				}

				// Here we read only one byte.
				target[ind_target] = hex_byte[0];
				++ind_target;
			}

			status = value_data->set_buffer_length(ind_target);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else if (type == eap_configure_type_u32array)
		{
			status = remove_spaces(&expanded_value_buffer);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			u8_t * cursor = expanded_value_buffer.get_data(expanded_value_buffer.get_data_length());
			if (cursor == 0)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			const u8_t * const cursor_end = cursor + expanded_value_buffer.get_data_length();
			
			while(cursor < cursor_end)
			{
				u32_t integer = 0;
				cursor = read_u32_t(
					cursor,
					cursor_end,
					&integer);
				if (cursor == 0)
				{
					break;
				}

				status = value_data->add_data(&integer, sizeof(integer));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		else
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}

		return EAP_STATUS_RETURN(m_am_tools, status);
}


//-----------------------------------------------------------------

eap_status_e eap_file_config_c::store_configure(
	abs_eap_am_file_input_c * const file,
	const eap_variable_data_c * const line,
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map)
{
	eap_status_e status = eap_status_process_general_error;
	
	eap_variable_data_c name_buffer(m_am_tools);
	if (name_buffer.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c value_buffer(m_am_tools);
	if (value_buffer.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_variable_data_c value_data(m_am_tools);
	if (value_data.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}


	status = name_buffer.set_buffer_length(MAX_LINE_LENGTH);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	name_buffer.set_data_length(0ul);

	status = value_buffer.set_buffer_length(MAX_LINE_LENGTH);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	value_buffer.set_data_length(0ul);

	eap_configure_type_e type = eap_configure_type_none;

	if (line->compare(
			EAP_FILECONFIG_SECTION_END,
			EAP_FILECONFIG_SECTION_END_LENGTH) == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CONFIG: section ends.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_section_ends);
	}

	status = cnf_get_string(
		line,
		&name_buffer,
		&value_buffer,
		&type);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	if (name_buffer.compare_length(
			EAP_FILECONFIG_SECTION,
			EAP_FILECONFIG_SECTION_LENGTH,
			EAP_FILECONFIG_SECTION_LENGTH) == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CONFIG: section %s.\n"),
			 name_buffer.get_data(name_buffer.get_data_length())));

		status = name_buffer.set_start_offset(EAP_FILECONFIG_SECTION_LENGTH);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_core_map_c<eap_config_value_c,
			abs_eap_core_map_c,
			eap_variable_data_c> * const section_map
			= new eap_core_map_c<
			eap_config_value_c,
			abs_eap_core_map_c,
			eap_variable_data_c>(m_am_tools, this);

		eap_automatic_variable_c<eap_core_map_c<
			eap_config_value_c,
			abs_eap_core_map_c,
			eap_variable_data_c> >
			automatic_section_map(m_am_tools, section_map);

		if (section_map == 0
			|| section_map->get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = read_section(file, section_map);
		if (status == eap_status_section_ends)
		{
			// Add subsection.
			eap_config_value_c * config = new eap_config_value_c(m_am_tools);

			eap_automatic_variable_c<eap_config_value_c>
				automatic_config(m_am_tools, config);

			if (config == 0
				|| config->get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			config->set_type(eap_configure_type_subsection);

			config->set_subsection(section_map);
			automatic_section_map.do_not_free_variable();
			
			status = convert_value(
				&m_config_map, // Note here we use the global name space.
				&value_buffer,
				type,
				&value_data);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			{
				// selector of the section is <name_buffer>:<value_data>.
				// section:example=string:match => example:match
				status = name_buffer.add_data(
					EAP_FILECONFIG_SECTION_SEPARATOR,
					EAP_FILECONFIG_SECTION_SEPARATOR_LENGTH);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = name_buffer.add_data(&value_data);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = name_buffer.add_end_null();
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}

			eap_variable_data_c selector(m_am_tools);
			if (selector.get_is_valid() == false)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}

			status = selector.set_copy_of_buffer(
				name_buffer.get_data(),
				name_buffer.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = config_map->add_handler(&selector, config);
			if (status == eap_status_ok)
			{
				automatic_config.do_not_free_variable();
			}
			else if (status == eap_status_handler_exists_error)
			{
				// This is dublicate subsection.
				// We will skip this.
				EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
								(EAPL("ERROR: CONFIG: section %s is already defined.\n"),
								 name_buffer.get_data(name_buffer.get_data_length())));

				return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
			}
			else if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DATA_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("CONFIG: subsection name"), 
				 name_buffer.get_data(), 
				 name_buffer.get_data_length()));

			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_CONFIGURE_DATA,
			(EAPL("CONFIG: check subsection %s.\n"),
			 name_buffer.get_data(name_buffer.get_data_length())));

		eap_configuration_field_template_c<MAX_LINE_LENGTH> * const tmp_name
			= new eap_configuration_field_template_c<MAX_LINE_LENGTH>;
	
		eap_automatic_variable_c<eap_configuration_field_template_c<MAX_LINE_LENGTH> >
			automatic_tmp_name(m_am_tools, tmp_name);
	
		if (tmp_name == 0
			|| tmp_name->get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = tmp_name->set_fields(
			m_am_tools,
			name_buffer.get_data(name_buffer.get_data_length()),
			type,
			false);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c check(m_am_tools);
		if (check.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = read_configure(
			config_map,
			tmp_name->get_field(),
			&check,
			&type,
			true);
		if (status == eap_status_ok)
		{
			status = name_buffer.add_end_null();
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			// This subsection is already defined.
#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
			printf("WARNING: CONFIG: subsection %s is already defined.\n",
				   name_buffer.get_data(name_buffer.get_data_length()));
#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
			
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
							(EAPL("WARNING: CONFIG: subsection %s is already defined.\n"),
							 name_buffer.get_data(name_buffer.get_data_length())));

			// We will skip the dublicate section.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}

		//-------------------------------------------------------------------------------

		eap_config_value_c * config = new eap_config_value_c(m_am_tools);

		eap_automatic_variable_c<eap_config_value_c>
			automatic_config(m_am_tools, config);

		if (config == 0
			|| config->get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		config->set_type(type);

		status = convert_value(
			&m_config_map, // Note here we use the global name space.
			&value_buffer,
			type,
			&value_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = config->get_data()->set_copy_of_buffer(
			&value_data);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c selector(m_am_tools);
		if (selector.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = selector.set_copy_of_buffer(
			tmp_name->get_field()->get_field(),
			tmp_name->get_field()->get_field_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = config_map->add_handler(&selector, config);
		if (status == eap_status_ok)
		{
			automatic_config.do_not_free_variable();
		}
		else //if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CONFIG: option added"),
			 tmp_name->get_field()->get_field(),
			 tmp_name->get_field()->get_field_length()));
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CONFIG: data"), 
			 config->get_data()->get_data(), 
			 config->get_data()->get_data_length()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("CONFIG: option type %d=%s\n"),
			 config->get_type(),
			 eap_configuration_field_c::get_configure_type_string(config->get_type())));

		//-----------------------------------------------------------------------------

	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::find_rvalue(
	const eap_variable_data_c * const config_param,
	bool * const read_env_value,
	eap_variable_data_c * const param_name,
	eap_variable_data_c * const param_value
	)
{
	const u8_t * rvalue = 0;
	const u8_t *env_value = 0;

	if (config_param == 0
		|| read_env_value == 0
		|| param_name == 0
		|| param_value == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u8_t * const param = config_param->get_data(config_param->get_data_length());
	if (param == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	const u8_t * const param_end
		= config_param->get_data(config_param->get_data_length())
		+ config_param->get_data_length();
	if (param_end == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	for (rvalue = param; *rvalue; rvalue++)
	{
		if (*rvalue == '=')
		{
			break;
		}
	}
	
	if (*rvalue == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// Check are there defined environment variable to override the file configuration.
	{
		// backup spaces.
		const u8_t *tmp_param_end = rvalue;

		for (tmp_param_end--
				 ; m_am_tools->isspace(*tmp_param_end)
				 || *tmp_param_end == '\r'
				 || *tmp_param_end == '\n'
				 || *tmp_param_end == '='
				 ; tmp_param_end--)
		{
			/* empty */
		}

		tmp_param_end++;
		u32_t length = tmp_param_end - param;


		eap_status_e status = param_name->add_data(param, length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = param_name->add_end_null();
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_variable_data_c env_value_buffer(m_am_tools);
		if (env_value_buffer.get_is_valid() == false)
		{
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		eap_status_e env_status = m_am_tools->getenv(
			param_name,
			&env_value_buffer);
		if (env_status == eap_status_ok)
		{
			env_value = env_value_buffer.get_data(env_value_buffer.get_data_length());
		}
		else
		{
			env_value = 0;
		}

		if (env_value != 0)
		{
			rvalue = env_value;
			length = m_am_tools->strlen(reinterpret_cast<const char *>(rvalue));
			*read_env_value = true;
		}
		else
		{
			rvalue = tmp_param_end;

			for (; *rvalue; rvalue++)
			{
				if (*rvalue == '=')
				{
					break;
				}
			}
			
			for (rvalue++; m_am_tools->isspace(*rvalue) || *rvalue == '\r' || *rvalue == '\n'; rvalue++){
				/* empty */
			}

			if (*rvalue == 0)
			{
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
			}

			length = param_end - rvalue;
		}

		// There is overriding environment variable.
		status = param_value->set_copy_of_buffer(rvalue, length);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		status = param_value->add_end_null();
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::cnf_parse_value(
	const eap_variable_data_c * const found_type_value,
	const eap_variable_data_c * const found_type_name,
	eap_configure_type_e * const parsed_type,
	eap_variable_data_c * const parsed_type_value,
	const bool is_environment_variable)
{
	if (found_type_value == 0
		|| found_type_name == 0
		|| parsed_type == 0
		|| parsed_type_value == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	*parsed_type = eap_configure_type_none;

	u32_t ind;
	for (ind = 0u; ind < sizeof(eap_configure_type_id)/sizeof(eap_configure_type_id[0]); ind++)
	{
		if (!m_am_tools->memcmp(
				eap_configure_type_id[ind].id,
				found_type_value->get_data(found_type_value->get_data_length()),
				eap_configure_type_id[ind].id_length))
		{
			*parsed_type = eap_configure_type_id[ind].type;
			break;
		}
	}

	u32_t value_length = found_type_value->get_data_length();

	eap_variable_data_c tmp_buffer(m_am_tools);
	if (tmp_buffer.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = tmp_buffer.set_buffer_length(MAX_LINE_LENGTH);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	tmp_buffer.set_data_length(MAX_LINE_LENGTH);

	u8_t * const tmp_value_buffer = tmp_buffer.get_buffer(MAX_LINE_LENGTH);
	if (tmp_value_buffer == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u8_t * used_type_value = found_type_value->get_data(found_type_value->get_data_length());
	if (used_type_value == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (*parsed_type == eap_configure_type_none)
	{
		// No type defined.
		if (is_environment_variable == true)
		{
			// Environment variable without type is handled as a string type.
			*parsed_type = eap_configure_type_string;
			ind = *parsed_type;
			m_am_tools->memmove(
				tmp_value_buffer,
				eap_configure_type_id[ind].id,
				eap_configure_type_id[ind].id_length);
			m_am_tools->memmove(
				tmp_value_buffer+eap_configure_type_id[ind].id_length,
				found_type_value->get_data(found_type_value->get_data_length()),
				value_length);
			value_length = eap_configure_type_id[ind].id_length+value_length;
			tmp_value_buffer[value_length] = 0;
			used_type_value = tmp_value_buffer;
		}
		else
		{
			#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
				printf("ERROR: CONFIG: no subsection type: %s=%s\n",
					found_type_name->get_data(found_type_name->get_data_length()),
					found_type_value->get_data(found_type_value->get_data_length()));
			#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
							(EAPL("ERROR: CONFIG: no subsection type: %s=%s\n"),
							found_type_name->get_data(found_type_name->get_data_length()),
							found_type_value->get_data(found_type_value->get_data_length())));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	}


	const u8_t * value_end = used_type_value+value_length;

	// Remove separator and spaces.
	for (value_end--
			 ; used_type_value < value_end
			 && (m_am_tools->isspace(*value_end)
				 || *value_end == '='
				 || *value_end == '\r'
				 || *value_end == '\n')
			 ; value_end--)
	{
		/* empty */
		--value_length;
	}
	++value_end;

	const u32_t tmp_length = value_end - used_type_value;

	u32_t len = tmp_length - eap_configure_type_id[ind].id_length;

	status = parsed_type_value->add_data(
		used_type_value+eap_configure_type_id[ind].id_length,
		len);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = parsed_type_value->add_end_null();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));

	if (is_environment_variable == true)
	{
		#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
			printf("CONFIG: %s=%s%s; from environment variable\n",
				   found_type_name->get_data(found_type_name->get_data_length()),
				   eap_configure_type_id[ind].id,
				   parsed_type_value->get_data(parsed_type_value->get_data_length()));
		#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
						(EAPL("CONFIG: %s=%s%s; from environment variable\n"),
						 found_type_name->get_data(found_type_name->get_data_length()),
						 eap_configure_type_id[ind].id,
						 parsed_type_value->get_data(parsed_type_value->get_data_length())));
	}
	else
	{
		#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
			printf("CONFIG: %s=%s%s\n",
				   found_type_name->get_data(found_type_name->get_data_length()),
				   eap_configure_type_id[ind].id,
				   parsed_type_value->get_data(parsed_type_value->get_data_length()));
		#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT,
						(EAPL("CONFIG: %s=%s%s\n"),
						 found_type_name->get_data(found_type_name->get_data_length()),
						 eap_configure_type_id[ind].id,
						 parsed_type_value->get_data(parsed_type_value->get_data_length())));
	}
	
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::cnf_get_string(
	const eap_variable_data_c * const param,
	eap_variable_data_c * const param_name,
	eap_variable_data_c * const param_value,
	eap_configure_type_e * const type)
{
	if (param == 0
		|| param_name == 0
		|| param_value == 0
		|| type == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	bool env_value = false;

	*type = eap_configure_type_none;

	// Returned value could be pointer to environment value.
	// Do not modify returned value.
	eap_status_e status = find_rvalue(
		param,
		&env_value,
		param_name,
		param_value
		);
	
	if (status != eap_status_ok)
	{
		#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)
			printf("ERROR: CONFIG: illegal subsection: %s\n",
				   param->get_data(param->get_data_length()));
		#endif //#if defined(EAP_FILE_CONFIG_USE_CONSOLE_PRINTS)

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CONFIG: illegal subsection: %s\n"),
			 param->get_data(param->get_data_length())));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
	}

	eap_variable_data_c parsed_value(m_am_tools);
	if (parsed_value.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = cnf_parse_value(
		param_value,
		param_name,
		type,
		&parsed_value,
		env_value);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = param_value->set_copy_of_buffer(&parsed_value);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = param_value->add_end_null();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::read_subsections(
	abs_eap_am_file_input_c * const file,
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map)
{
	eap_variable_data_c line(m_am_tools);
	if (line.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_ok;

	// This sets the pre-allocated buffer.
	status = line.set_buffer_length(MAX_LINE_LENGTH);

	for (;status == eap_status_ok;)
	{
		status = get_subsect(file, &line);
		if (status == eap_status_end_of_file)
		{
			// End of file reached.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = store_configure(file, &line, config_map);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::read_section(
	abs_eap_am_file_input_c * const file,
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map)
{
	eap_variable_data_c line(m_am_tools);
	if (line.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = eap_status_ok;

	// This sets the pre-allocated buffer.
	status = line.set_buffer_length(MAX_LINE_LENGTH);

	while (status == eap_status_ok)
	{
		status = get_subsect(file, &line);
		if (status == eap_status_end_of_file)
		{
			// End of file reached.
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
		else if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (line.compare(
				EAP_FILECONFIG_SECTION_START,
				EAP_FILECONFIG_SECTION_START_LENGTH) == 0)
		{
			// Starts new section block.
			status = read_subsections(
				file,
				config_map);

			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		else
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: CONFIG: section start '{' is missing.\n")));
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::remove_spaces(eap_variable_data_c * const buffer)
{
	if (buffer == 0
		|| buffer->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	u32_t length = buffer->get_data_length();
	const u8_t * source = buffer->get_data(length);
	u8_t * destination = buffer->get_data(length);
	u32_t ind_dest(0ul);

	for (u32_t ind = 0ul; ind < length; ind++)
	{
		const u8_t character = source[ind];

		if (m_am_tools->isspace(character) == false)
		{
			destination[ind_dest] = character;
			++ind_dest;
		}
	} // for()

	eap_status_e status = buffer->set_data_length(ind_dest);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::remove_leading_spaces(
	eap_variable_data_c * const line)
{
	if (line->get_data_length() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}

	u8_t * const begin = line->get_data(line->get_data_length());
	if(begin == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
	}

	for (u32_t ind = 0; ind < line->get_data_length(); ind++)
	{
		if (begin[ind] != ' '
			&& begin[ind] != '\t')
		{
			eap_status_e status = line->set_start_offset(ind);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::file_read_line(
	abs_eap_am_file_input_c * const file,
	eap_variable_data_c * const line)
{
	eap_status_e status(eap_status_ok);
	bool line_continues(true);

	eap_variable_data_c tmp_line(m_am_tools);
	if (tmp_line.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	const u32_t TMP_LINE_BUFFER_INITIAL_LENGTH = 256ul;

	status = tmp_line.set_buffer_length(TMP_LINE_BUFFER_INITIAL_LENGTH);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	// This is small optimization that does not free the old buffer.
	status = line->reset_start_offset_and_data_length();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	do
	{
		status = tmp_line.reset_start_offset_and_data_length();
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = file->file_read_line(&tmp_line);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_CONFIGURE_DATA,
			(EAPL("Configure line"), 
			 tmp_line.get_data(), 
			 tmp_line.get_data_length()));

		status = remove_leading_spaces(&tmp_line);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_CONFIGURE_DATA,
			(EAPL("No spaces line"), 
			 tmp_line.get_data(), 
			 tmp_line.get_data_length()));

		if (tmp_line.get_data_length() > 0ul)
		{
			u8_t * last_char = tmp_line.get_buffer_offset(
				tmp_line.get_data_length() - 1ul,
				sizeof(u8_t));

			if (last_char  != 0
				&& *last_char == '\\')
			{
				// If the last character in the line is '\' then the line continues to the next line.
				tmp_line.set_data_length(tmp_line.get_data_length() - 1ul);
			}
			else
			{
				line_continues = false;
			}
		}
		else
		{
			line_continues = false;
		}

		status = line->add_data(&tmp_line);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

	} while(line_continues == true);


	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_CONFIGURE_DATA,
		(EAPL("Configure line"), 
		 tmp_line.get_data(), 
		 tmp_line.get_data_length()));

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::get_subsect(
	abs_eap_am_file_input_c * const file,
	eap_variable_data_c * const line)
{
	if( file == 0
		|| line == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status(eap_status_ok);
	
	for(;status == eap_status_ok;)
	{
		status = file_read_line(file, line);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_CONFIGURE_DATA,
			(EAPL("Configure line"), 
			 line->get_data(line->get_data_length()), 
			 line->get_data_length()));

		// error or end of file
		if(status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = remove_leading_spaces(line);
		if(status != eap_status_ok)
		{
			// Skip this error.
			status = eap_status_ok;
			continue;
		}

		// too short line, ignore
		if(line->get_data_length() < 1ul)
		{
			continue;
		}

		u8_t * const result = line->get_data(line->get_data_length());
		if(result == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_process_general_error);
		}
		
		// ignore the lines starting with newline, space, tab or '#'
		if ((*result == '\r')
			|| (*result == '\n')
			|| (*result == ' ')
			|| (*result == '\t')
			|| (*result == '#'))
		{
			continue;
		}
		else
		{
			// OK we get a line.
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::read_configure(
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
	const eap_configuration_field_c * const field,
	eap_variable_data_c* const data,
	eap_configure_type_e * const configuration_data_type,
	const bool existence_test)
{
	eap_status_e status = eap_status_process_general_error;

	eap_variable_data_c selector(m_am_tools);
	if (selector.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	status = selector.set_buffer(
		field->get_field(),
		field->get_field_length(),
		false,
		false);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_config_value_c *config = config_map->get_handler(&selector);

	if (config != 0)
	{
		status = data->set_copy_of_buffer(config->get_data());

		if (status == eap_status_ok)
		{
			*configuration_data_type = config->get_type();
		}
		else
		{
			*configuration_data_type = eap_configure_type_none;
		}
	}
	else
	{
		if (existence_test == false)
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: CONFIG: unknown option"),
				 field->get_field(),
				 field->get_field_length()));
		}
		status = eap_status_illegal_configure_field;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return status; // Here EAP_STATUS_RETURN() macro is too noisy.
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::read_all_configurations(
	const eap_configuration_field_c * const /* field */,
	eap_variable_data_c* const data,
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map)
{
	eap_status_e status = eap_status_process_general_error;

	/**
	 * Here is a figure of message data composed of Attribute-Value Pairs (See eap_tlv_header_c).
	 * Value data follows eap_tlv_message_data_c.
	 * @code
	 *  Configuration data:
	 *  0                   1                   2                   3   
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 * |       Type = eap_tlv_message_type_configuration_option        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                             Length = 8+4+8+m+8+n              |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |       Type = eap_tlv_message_type_u32_t                       |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                             Length = 4                        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |          option type eap_configure_type_hex_data              |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |       Type = eap_tlv_message_type_variable_data               |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | First configuration option
	 * |                             Length = m                        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |               Value (m octets) option name                    |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |       Type = eap_tlv_message_type_variable_data               |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                             Length = n                        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |               Value (n octets) option data                    |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 * |       Type = eap_tlv_message_type_configuration_option        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                             Length = 8+4+8+m+8+4              |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |       Type = eap_tlv_message_type_u32_t                       |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                             Length = 4                        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |          option type  eap_configure_type_u32_t                |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |       Type = eap_tlv_message_type_variable_data               |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  | Second configuration option
	 * |                             Length = m                        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |               Value (m octets) option name                    |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |       Type = eap_tlv_message_type_u32_t                       |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |                             Length = 4                        |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  |
	 * |               Value option data 32-bit integer                |  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ -+
	 *
	 * @endcode
	 * 
	 */

	u32_t size_of_data(0ul);
	u32_t ind(0ul);

	eap_process_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	for (ind = 0ul; ind < config_map->get_atom_count(); ++ind)
	{
		const eap_state_map_atom_c<eap_config_value_c, eap_variable_data_c> * atom = config_map->get_atom(ind);
		while (atom != 0)
		{
			u32_t size = message.get_payload_size(
					atom->get_selector(),
					atom->get_const_object());

			if (size > 0ul)
			{
				// The extra size of header is added because the whole allocated message size includes all headers.
				// The get_payload_size() function calculates only payload of the option without the main header.
				size_of_data +=
					size
					+ eap_tlv_header_c::get_header_length();
			}
			else
			{
				// Some configuration objects are not included to message yet.
			}

			atom = atom->get_next_atom();
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CONFIG: data size %d\n"),
		 size_of_data));

	status = message.allocate_message_data_buffer(size_of_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	for (ind = 0ul; ind < config_map->get_atom_count(); ++ind)
	{
		const eap_state_map_atom_c<eap_config_value_c, eap_variable_data_c> * atom = config_map->get_atom(ind);
		while (atom != 0)
		{
			status = message.add_parameter_data(atom->get_selector(), atom->get_const_object());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			atom = atom->get_next_atom();
		}
	}

	status = data->set_copy_of_buffer(
		message.get_message_data(),
		message.get_message_data_length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::add_option(
	const eap_tlv_header_c * const option_header)
{
	eap_status_e status = eap_status_process_general_error;

	eap_process_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = message.set_message_data(option_header->get_value_length(), option_header->get_value(option_header->get_value_length()));
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> parameters(m_am_tools);

	status = message.parse_message_data(&parameters);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_config_value_c * config = new eap_config_value_c(m_am_tools);

	eap_automatic_variable_c<eap_config_value_c>
		automatic_config(m_am_tools, config);

	if (config == 0
		|| config->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	u32_t parameter_index(0ul);

	eap_variable_data_c selector(m_am_tools);
	if (selector.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	{
		const eap_tlv_header_c * const a_option_header = parameters.get_object(parameter_index);
		if (a_option_header == 0
			|| a_option_header->get_type() != eap_tlv_message_type_u32_t)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			status = eap_status_illegal_parameter;
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		u32_t value(0ul);

		status = message.get_parameter_data(
			a_option_header,
			&value);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		config->set_type(static_cast<eap_configure_type_e>(value));
	}

	++parameter_index;
	
	{
		const eap_tlv_header_c * const a_option_header = parameters.get_object(parameter_index);
		if (a_option_header == 0
			|| a_option_header->get_type() != eap_tlv_message_type_variable_data)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			status = eap_status_illegal_parameter;
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = message.get_parameter_data(
			a_option_header,
			&selector);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	
	++parameter_index;

	switch(config->get_type())
	{
	case eap_configure_type_string:
	case eap_configure_type_hex_data:
		{
			const eap_tlv_header_c * const a_option_header = parameters.get_object(parameter_index);
			if (a_option_header == 0
				|| a_option_header->get_type() != eap_tlv_message_type_variable_data)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

				status = eap_status_illegal_parameter;
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = message.get_parameter_data(
				a_option_header,
				config->get_data());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;
	case eap_configure_type_u32_t:
	case eap_configure_type_boolean:
		{
			const eap_tlv_header_c * const a_option_header = parameters.get_object(parameter_index);
			if (a_option_header == 0
				|| a_option_header->get_type() != eap_tlv_message_type_u32_t)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

				status = eap_status_illegal_parameter;
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			u32_t value(0ul);

			status = message.get_parameter_data(
				a_option_header,
				&value);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = config->get_data()->set_copy_of_buffer(&value, sizeof(value));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		break;
	case eap_configure_type_u32array:
		{
			const eap_tlv_header_c * const a_option_header = parameters.get_object(parameter_index);
			if (a_option_header == 0
				|| a_option_header->get_type() != eap_tlv_message_type_array)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

				status = eap_status_illegal_parameter;
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eap_process_tlv_message_data_c array_message(m_am_tools);

			if (array_message.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = array_message.set_message_data(a_option_header->get_value_length(), a_option_header->get_value(a_option_header->get_value_length()));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			eap_array_c<eap_tlv_header_c> array_parameters(m_am_tools);

			status = array_message.parse_message_data(&array_parameters);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			for (u32_t ind = 0ul; ind < array_parameters.get_object_count(); ++ind)
			{
				const eap_tlv_header_c * const a_option_header = array_parameters.get_object(ind);
				if (a_option_header == 0
					|| a_option_header->get_type() != eap_tlv_message_type_u32_t)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

					status = eap_status_illegal_parameter;
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				u32_t value(0ul);

				status = array_message.get_parameter_data(
					a_option_header,
					&value);
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}

				status = config->get_data()->add_data(&value, sizeof(value));
				if (status != eap_status_ok)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, status);
				}
			}
		}
		break;
	default:
		break;
	};

	status = m_config_map.add_handler(&selector, config);
	if (status == eap_status_ok)
	{
		automatic_config.do_not_free_variable();
	}
	else //if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("\n")));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CONFIG MESSAGE: option failed"),
			 selector.get_data(),
			 selector.get_data_length()));
		
		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: CONFIG MESSAGE: data"), 
			 config->get_data()->get_data(), 
			 config->get_data()->get_data_length()));

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: CONFIG MESSAGE: option type %d=%s\n"),
			 config->get_type(),
			 eap_configuration_field_c::get_configure_type_string(config->get_type())));

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("\n")));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CONFIG MESSAGE: option added"),
		 selector.get_data(),
		 selector.get_data_length()));
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("CONFIG MESSAGE: data"), 
		 config->get_data()->get_data(), 
		 config->get_data()->get_data_length()));

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CONFIG MESSAGE: option type %d=%s\n"),
		 config->get_type(),
		 eap_configuration_field_c::get_configure_type_string(config->get_type())));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_file_config_c::read_configuration_message(
	const eap_variable_data_c * const configuration_message)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_file_config_c::read_configuration_message(): data=0x%08x, length=%d\n"),
		configuration_message->get_data(),
		configuration_message->get_data_length()));

	EAP_TRACE_RETURN_STRING(m_am_tools, "returns: eap_file_config_c::read_configuration_message()");

	eap_status_e status = eap_status_process_general_error;

	eap_process_tlv_message_data_c message(m_am_tools);

	if (message.get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	status = message.set_message_data(configuration_message->get_data_length(), configuration_message->get_data());
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_array_c<eap_tlv_header_c> parameters(m_am_tools);

	status = message.parse_message_data(&parameters);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	for (u32_t ind = 0ul; ind < parameters.get_object_count(); ++ind)
	{
		const eap_tlv_header_c * const option_header = parameters.get_object(ind);
		if (option_header == 0
			|| option_header->get_type() != eap_tlv_message_type_configuration_option)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);

			status = eap_status_illegal_parameter;
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = add_option(option_header);
		if (status != eap_status_ok
			&& status != eap_status_handler_exists_error // Here we skip duplicate configuration values.
			)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = eap_status_ok;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

eap_status_e eap_file_config_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c* const data,
	eap_core_map_c<eap_config_value_c, abs_eap_core_map_c, eap_variable_data_c> * const config_map,
	const bool check_subsection_when_true)
{
	eap_status_e status = eap_status_process_general_error;

	eap_variable_data_c selector(m_am_tools);
	if (selector.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (check_subsection_when_true == true
		&& field->get_subsection() != 0)
	{
		status = selector.set_buffer(
			field->get_subsection());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("CONFIG: finds subsection name"), 
			 field->get_subsection()->get_data(), 
			 field->get_subsection()->get_data_length()));

		eap_config_value_c *config = config_map->get_handler(&selector);

		if (config != 0)
		{
			if (check_subsection_when_true == true
				&& config->get_type() == eap_configure_type_subsection)
			{
				if (config->get_subsection() != 0)
				{
					status = read_configure(
						field,
						data,
						config->get_subsection(),
						false);
					if (status == eap_status_ok)
					{
						// OK, section configuration found.
						EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
						return EAP_STATUS_RETURN(m_am_tools, status);
					}
				}
				else
				{
					EAP_TRACE_DATA_DEBUG(
						m_am_tools,
						TRACE_FLAGS_DEFAULT,
						(EAPL("WARNING: CONFIG: subsection not found"),
						 field->get_field(),
						 field->get_field_length()));
				}
			}
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: CONFIG: subsection not found"),
				 field->get_field(),
				 field->get_field_length()));
		}
	}



	{
		status = selector.set_buffer(
			field->get_field(),
			field->get_field_length(),
			false,
			false);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		eap_config_value_c *config = config_map->get_handler(&selector);

		if (config != 0)
		{
			if (field->get_type() != config->get_type())
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: CONFIG: option type failed: required %d=%s != actual %d=%s\n"),
					 field->get_type(),
					 eap_configuration_field_c::get_configure_type_string(field->get_type()),
					 config->get_type(),
					 eap_configuration_field_c::get_configure_type_string(config->get_type())));
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("WARNING: CONFIG: rear option type failed: %s\n"),
					 field->get_field()));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_type);
			}

			status = data->set_copy_of_buffer(config->get_data());

			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("CONFIG: value read from eap_file_config_c: %s\n"),
				 field->get_field()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("value"),
				 data->get_data(),
				 data->get_data_length()));
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: CONFIG: option not found"),
				 field->get_field(),
				 field->get_field_length()));
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: CONFIG: option type %d=%s\n"),
				 field->get_type(),
				 eap_configuration_field_c::get_configure_type_string(field->get_type())));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_configure_field);
		}

	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_file_config_c::read_configure(
	const eap_configuration_field_c * const field,
	eap_variable_data_c* const data)
{
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_file_config_c::read_configure()"),
		 field->get_field(),
		 field->get_field_length()));

	eap_status_e status(eap_status_process_general_error);

	if (field->get_type() == eap_configure_type_all_configurations
		&& field->compare(
			m_am_tools,
			cf_str_EAP_read_all_configurations.get_field()) == true)
	{
		status = read_all_configurations(
			field,
			data,
			&m_config_map);
	}
	else
	{
		status = read_configure(
			field,
			data,
			&m_config_map,
			true);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-----------------------------------------------------------------
