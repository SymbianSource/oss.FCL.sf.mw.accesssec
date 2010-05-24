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

#if !defined(_EAP_CONFIGURATION_FIELD_H_)
#define _EAP_CONFIGURATION_FIELD_H_

#include "eap_am_memory.h"
#include "eap_am_types.h"
#include "eap_am_tools.h"


const char EAP_FILECONFIG_SECTION_SEPARATOR[] = ":";
const u32_t EAP_FILECONFIG_SECTION_SEPARATOR_LENGTH = (sizeof(EAP_FILECONFIG_SECTION_SEPARATOR)-1ul);


//--------------------------------------------------------------------------------------------------

enum eap_configure_type_e
{
	eap_configure_type_none,
	eap_configure_type_u32_t,
	eap_configure_type_boolean,
	eap_configure_type_string,
	eap_configure_type_hex_data,
	eap_configure_type_u32array,
	eap_configure_type_section,
	eap_configure_type_subsection,
	eap_configure_type_all_configurations, //< This is special type to read all configuration options. Data is in message format. Please see eap_tlv_message_data_c.
};

//--------------------------------------------------------------------------------------------------

class eap_configuration_field_c
{
public:

	~eap_configuration_field_c()
	{
		delete m_subsection_name;
		m_subsection_name = 0;
	}

	const bool get_is_secret() const
	{
		return m_is_secret;
	}

	const eap_configure_type_e get_type() const
	{
		return m_type;
	}

	const u32_t get_field_length() const
	{
		return m_field_length;
	}

	eap_config_string get_field() const
	{
		return m_field;
	}

	eap_status_e set_subsection(
		abs_eap_am_tools_c * const tools,
		const eap_configuration_field_c * const p_subsection_name,
		const eap_variable_data_c * const p_subsection_value)
	{
		delete m_subsection_name;
		m_subsection_name = 0;

		m_subsection_name = new eap_variable_data_c(tools);
		if (m_subsection_name == 0)
		{
			return EAP_STATUS_RETURN(tools, eap_status_allocation_error);
		}

		eap_status_e status = m_subsection_name->add_data(
			p_subsection_name->get_field(),
			p_subsection_name->get_field_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(tools, status);
		}

		status = m_subsection_name->add_data(
			EAP_FILECONFIG_SECTION_SEPARATOR,
			EAP_FILECONFIG_SECTION_SEPARATOR_LENGTH);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(tools, status);
		}

		status = m_subsection_name->add_data(
			p_subsection_value->get_data(),
			p_subsection_value->get_data_length());
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(tools, status);
		}

		return EAP_STATUS_RETURN(tools, eap_status_ok);
	}

	const eap_variable_data_c * get_subsection() const
	{
		return m_subsection_name;
	}

	bool compare(
		abs_eap_am_tools_c * const tools,
		const eap_configuration_field_c * const field) const
	{
		return field->get_field_length() == get_field_length()
			&& tools->memcmp(
				field->get_field(),
				get_field(),
				field->get_field_length()) == 0;
	}


	bool compare(
		abs_eap_am_tools_c * const tools,
		const eap_variable_data_c * const data) const
	{
		return data->get_data_length() == get_field_length()
			&& tools->memcmp(
				data->get_data(),
				get_field(),
				data->get_data_length()) == 0;
	}

	eap_configuration_field_c * copy(
		abs_eap_am_tools_c * const tools,
		const eap_configuration_field_c * const p_subsection_name,
		const eap_variable_data_c * const p_subsection_value) const
	{
		// This allocates memory for object and following field.
		u32_t data_length = sizeof(eap_configuration_field_c) + m_field_length;
		u8_t * const new_buffer = new u8_t[data_length];
		if (new_buffer == 0)
		{
			return 0;
		}

		eap_configuration_field_c * tmp = reinterpret_cast<eap_configuration_field_c *>(new_buffer);

		tools->memmove(tmp, this, data_length);

		eap_status_e status = tmp->set_subsection(
			tools,
			p_subsection_name,
			p_subsection_value);
		if (status != eap_status_ok
			|| tmp->get_subsection() == 0)
		{
			delete tmp;
			tmp = 0;
		}

		return tmp;
	}

	static eap_const_string get_configure_type_string(const eap_configure_type_e type)
	{
		#if defined(USE_EAP_TRACE_STRINGS)
		EAP_IF_RETURN_STRING(type, eap_configure_type_none)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_u32_t)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_boolean)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_string)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_hex_data)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_u32array)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_section)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_subsection)
		else EAP_IF_RETURN_STRING(type, eap_configure_type_all_configurations)
		else
		#endif // #if defined(USE_EAP_TRACE_STRINGS)
		{
			EAP_UNREFERENCED_PARAMETER(type);
			return EAPL("Unknown EAP-configure_type");
		}
	}

private:
	bool                 m_is_secret;
	eap_configure_type_e m_type;
	eap_variable_data_c *m_subsection_name;
	u32_t                m_field_length;
	i8_t                 m_field[1];
};

//--------------------------------------------------------------------------------------------------

template <u32_t buffer_length>
class eap_configuration_field_template_c
{
public:
	inline const eap_configuration_field_c * get_field() const;

	inline eap_status_e set_fields(
		abs_eap_am_tools_c* const am_tools,
		const void * const field,
		const eap_configure_type_e type,
		const bool is_secret)
	{
		m_is_secret = false;
		m_type = eap_configure_type_none;

		u32_t field_length = (static_cast<eap_am_tools_c *> (am_tools))->strlen(
			static_cast<const eap_char *>(field));
		if (field_length+1 > buffer_length)
		{
			m_field_length = 0ul;
			m_field[0] = '\0';
			return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
		}

		m_is_secret = is_secret;
		m_type = type;
		am_tools->memmove(m_field, field, field_length+1);
		m_field_length = field_length;

		return EAP_STATUS_RETURN(am_tools, eap_status_ok);
	}

	inline bool get_is_valid() const
	{
		EAP_STATIC_ASSERT(sizeof(eap_configuration_field_template_c<buffer_length>) >= sizeof(eap_configuration_field_c));
		return true;
	}


public:
	bool                 m_is_secret;
	eap_configure_type_e m_type;
	eap_variable_data_c *m_subsection_name;
	u32_t                m_field_length;
	i8_t                 m_field[buffer_length];
};

template <u32_t buffer_length>
inline const eap_configuration_field_c * eap_configuration_field_template_c<buffer_length>::get_field() const
{
	return reinterpret_cast<const eap_configuration_field_c *>(this);
}

#define EAP_CONFIGURATION_FIELD(name, field, type, is_secret) \
	static const eap_configuration_field_template_c<sizeof(field)> name \
		EAP_ATTRIBUTE_UNUSED = {is_secret, type, 0, sizeof(field)-1, field}; \
	EAP_AM_CONFIGURATION_FIELD_LITERAL(name, field)

//--------------------------------------------------------------------------------------------------


#endif //#if !defined(_EAP_CONFIGURATION_FIELD_H_)

//--------------------------------------------------


// End.
