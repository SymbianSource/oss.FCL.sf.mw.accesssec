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

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 23 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_expanded_type.h"
#include "eap_header.h"

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c::~eap_expanded_type_c()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c::eap_expanded_type_c()
{
	m_vendor_id = eap_type_vendor_id_ietf;
	m_vendor_type = static_cast<u32_t>(eap_type_none);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c::eap_expanded_type_c(
	const eap_type_vendor_id_e vendor_id,
	const u32_t vendor_type)
{
	m_vendor_id = vendor_id;
	m_vendor_type = vendor_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c::eap_expanded_type_c(
	const eap_type_ietf_values_e type)
{
	m_vendor_id = eap_type_vendor_id_ietf;
	m_vendor_type = static_cast<u32_t>(type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::get_is_valid() const
{
	return true;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::get_is_valid_data() const
{
	return get_is_valid();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c * eap_expanded_type_c::copy() const
{
	eap_expanded_type_c * const new_entry = new eap_expanded_type_c;

	if (new_entry == 0
		|| new_entry->get_is_valid() == false)
	{
		delete new_entry;
		return 0;
	}

	new_entry->set_eap_type_values(m_vendor_id, m_vendor_type);

	return new_entry;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::is_expanded_type(const eap_type_ietf_values_e eap_type)
{
	return (eap_type == eap_type_expanded_type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::is_ietf_type(const eap_expanded_type_c eap_type)
{
	return (eap_type.get_vendor_id() == eap_type_vendor_id_ietf
			&& eap_type.get_vendor_type() < eap_type_expanded_type);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_expanded_type_c::get_type_data(
	abs_eap_am_tools_c * const am_tools,
	eap_type_ietf_values_e * const type) const
{
	if (type == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	if (m_vendor_type < eap_type_expanded_type
		&& m_vendor_id == eap_type_vendor_id_ietf)
	{
		*type = static_cast<eap_type_ietf_values_e>(m_vendor_type);
	}
	else 
	{
		// This is EAP type of other vendor than IETF.
		// This cannot be denoted in eap_type_ietf_values_e.
		*type = static_cast<eap_type_ietf_values_e>(m_vendor_type);
	}

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_expanded_type_c::get_type_data(
	abs_eap_am_tools_c * const am_tools,
	eap_expanded_type_c * const type) const
{
	if (type == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	*type = *this;

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_expanded_type_c::get_expanded_type_data(
	abs_eap_am_tools_c * const am_tools,
	eap_variable_data_c * const data) const
{
	if (data == 0
		|| data->get_is_valid() == false)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = data->reset();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(am_tools, status);
	}

	status = data->set_buffer_length(get_eap_expanded_type_size());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(am_tools, status);
	}

	status = data->set_data_length(get_eap_expanded_type_size());
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(am_tools, status);
	}

	u32_t offset = 0ul;

	{
		u8_t * const ietf_type = static_cast<u8_t *>(data->get_data_offset(offset, m_ietf_type_size));
		if (ietf_type == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_ietf_type_size;

		*ietf_type = static_cast<u8_t>(eap_type_expanded_type);
	}

	{
		u8_t * const vendor_id = data->get_data_offset(offset, m_vendor_id_size);
		if (vendor_id == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_vendor_id_size;

		status = eap_write_u24_t_network_order(
			vendor_id,
			m_vendor_id_size,
			m_vendor_id);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(am_tools, status);
		}
	}

	{
		u8_t * const vendor_type = data->get_data_offset(offset, m_vendor_type_size);
		if (vendor_type == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_vendor_type_size;

		status = eap_write_u32_t_network_order(
			vendor_type,
			m_vendor_type_size,
			m_vendor_type);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_expanded_type_c::set_expanded_type_data(
	abs_eap_am_tools_c * const am_tools,
	const eap_variable_data_c * const data)
{
	if (data == 0
		|| data->get_data_length() != get_eap_expanded_type_size()
		|| data->get_data(data->get_data_length()) == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	u32_t offset = 0ul;

	{
		u8_t * const ietf_type = static_cast<u8_t *>(data->get_data_offset(offset, m_ietf_type_size));
		if (ietf_type == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_ietf_type_size;

		if (static_cast<eap_type_ietf_values_e>(*ietf_type) != eap_type_expanded_type)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
	}

	{
		u8_t * const vendor_id = data->get_data_offset(offset, m_vendor_id_size);
		if (vendor_id == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_vendor_id_size;

		m_vendor_id = static_cast<eap_type_vendor_id_e>(eap_read_u24_t_network_order(vendor_id, m_vendor_id_size));
	}

	{
		u8_t * const vendor_type = data->get_data_offset(offset, m_vendor_type_size);
		if (vendor_type == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_vendor_type_size;

		m_vendor_type = eap_read_u32_t_network_order(vendor_type, m_vendor_type_size);
	}

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_expanded_type_c::set_expanded_type_data(
	abs_eap_am_tools_c * const am_tools,
	const void * const data,
	const u32_t data_length)
{
	if (data_length != get_eap_expanded_type_size()
		|| data == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	u32_t offset = 0ul;

	{
		const u8_t * const ietf_type = &(reinterpret_cast<const u8_t *>(data)[offset]);
		if (ietf_type == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_ietf_type_size;

		if (static_cast<eap_type_ietf_values_e>(*ietf_type) != eap_type_expanded_type)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
	}

	{
		const u8_t * const vendor_id = &(reinterpret_cast<const u8_t *>(data)[offset]);
		if (vendor_id == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_vendor_id_size;

		m_vendor_id = static_cast<eap_type_vendor_id_e>(eap_read_u24_t_network_order(vendor_id, m_vendor_id_size));
	}

	{
		const u8_t * const vendor_type = &(reinterpret_cast<const u8_t *>(data)[offset]);
		if (vendor_type == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
		}
		offset += m_vendor_type_size;

		m_vendor_type = eap_read_u32_t_network_order(vendor_type, m_vendor_type_size);
	}

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_expanded_type_c::set_eap_type_values(
	const eap_type_vendor_id_e vendor_id,
	const u32_t vendor_type)
{
	m_vendor_id = vendor_id;
	m_vendor_type = vendor_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_type_vendor_id_e eap_expanded_type_c::get_vendor_id() const
{
	return m_vendor_id;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_expanded_type_c::get_vendor_type() const
{
	return m_vendor_type;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_expanded_type_c::get_eap_expanded_type_size()
{
	return m_eap_expanded_type_size;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::operator == (const eap_type_ietf_values_e right_type_value) const
{
	if (m_vendor_id != eap_type_vendor_id_ietf)
	{
		return false;
	}
	else if (m_vendor_type != static_cast<u32_t>(right_type_value))
	{
		return false;
	}
	else
	{
		return true;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::operator != (const eap_type_ietf_values_e right_type_value) const
{
	return !(*this == right_type_value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::operator == (const eap_expanded_type_c &right_type_value) const
{
	if (m_vendor_id != right_type_value.get_vendor_id())
	{
		return false;
	}
	else if (m_vendor_type != right_type_value.get_vendor_type())
	{
		return false;
	}
	else
	{
		return true;
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool eap_expanded_type_c::operator != (const eap_expanded_type_c &right_type_value) const
{
	return !(*this == right_type_value);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c &eap_expanded_type_c::operator = (const eap_type_ietf_values_e right_type_value)
{
	m_vendor_id = eap_type_vendor_id_ietf; ///< Here we use only 24 least significant bits.
	m_vendor_type = static_cast<u32_t>(right_type_value);

	return *this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c &eap_expanded_type_c::operator = (const eap_expanded_type_c &right_type_value)
{
	m_vendor_id = right_type_value.get_vendor_id(); ///< Here we use only 24 least significant bits.
	m_vendor_type = right_type_value.get_vendor_type();

	return *this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_expanded_type_c *eap_expanded_type_c::operator & ()
{
	return this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT const eap_expanded_type_c *eap_expanded_type_c::operator & () const
{
	return this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_expanded_type_c::read_type(
	abs_eap_am_tools_c * const am_tools,
	const u32_t index,
	const void * const p_buffer,
	const u32_t buffer_length,
	eap_expanded_type_c * const type
	)
{
	if (p_buffer == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	const u8_t * const buffer = static_cast<const u8_t *>(p_buffer);

	if (buffer_length >= eap_expanded_type_c::m_ietf_type_size)
	{
		const u8_t * const type_data = buffer;
		if (type_data != 0)
		{
			eap_type_ietf_values_e ietf_eap_type = static_cast<eap_type_ietf_values_e>(*type_data);

			if (ietf_eap_type < eap_type_expanded_type
				&& buffer_length >= eap_expanded_type_c::m_ietf_type_size*(index+1))
			{
				if (index > 0ul)
				{
					const u8_t * const offset_type_data =
						&(buffer[eap_expanded_type_c::m_ietf_type_size*index]);
					if (offset_type_data != 0)
					{
						*type = static_cast<eap_type_ietf_values_e>(*offset_type_data);
						return EAP_STATUS_RETURN(am_tools, eap_status_ok);
					}
					else
					{
						return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
					}
				}
				else
				{
					*type = ietf_eap_type;
					return EAP_STATUS_RETURN(am_tools, eap_status_ok);
				}
			}
			else if (ietf_eap_type == eap_type_expanded_type
				&& buffer_length >= eap_header_base_c::get_expanded_type_field_length()*(index+1ul))
			{
				//  0                   1                   2                   3
				//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |     Type      |               Vendor-Id                       |
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |                          Vendor-Type                          |
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
				// |              Vendor data...
				// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

				eap_type_ietf_values_e ietf_eap_type(eap_type_none);

				{
					const u8_t * const offset_type_data =
						&(buffer[eap_header_base_c::get_expanded_ietf_type_offset()
									+eap_header_base_c::get_expanded_type_field_length()*index]);
					if (offset_type_data != 0)
					{
						ietf_eap_type = static_cast<eap_type_ietf_values_e>(*offset_type_data);
					}
					else
					{
						EAP_UNREFERENCED_PARAMETER(ietf_eap_type);
						return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
					}
				}

				eap_type_vendor_id_e vendor_id_value = eap_type_vendor_id_ietf;

				{
					const u8_t * const vendor_id =
						&(buffer[eap_header_base_c::get_expanded_vendor_id_offset()
									+eap_header_base_c::get_expanded_type_field_length()*index]);
					if (vendor_id == 0)
					{
						return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
					}

					vendor_id_value = static_cast<eap_type_vendor_id_e>(
						eap_read_u24_t_network_order(
							vendor_id,
							3ul*sizeof(u8_t)));
				}

				u32_t vendor_type_value = 0ul;

				{
					const u8_t * const vendor_type =
						&(buffer[eap_header_base_c::get_expanded_vendor_type_offset()
									+eap_header_base_c::get_expanded_type_field_length()*index]);
					if (vendor_type == 0)
					{
						return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
					}

					vendor_type_value = eap_read_u32_t_network_order(
						vendor_type,
						sizeof(u32_t));
				}

				type->set_eap_type_values(
					vendor_id_value,
					vendor_type_value);

				EAP_ASSERT_TOOLS(am_tools, (ietf_eap_type == eap_type_expanded_type));

				return EAP_STATUS_RETURN(am_tools, eap_status_ok);
			}
			else
			{
				return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
			}
		}
		else
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
		}
	}
	else
	{
		// NOTE, Every EAP-packet does not include EAP-type field.
		return EAP_STATUS_RETURN(am_tools, eap_status_ok);
	}
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_expanded_type_c::write_type(
	abs_eap_am_tools_c * const am_tools,
	const u32_t index,
	void * const p_buffer,
	const u32_t buffer_length,
	const bool write_extented_type_when_true,
	const eap_expanded_type_c p_type ///< The EAP type to be written.
	)
{
	if (p_buffer == 0)
	{
		EAP_UNREFERENCED_PARAMETER(am_tools);
		return EAP_STATUS_RETURN(am_tools, eap_status_illegal_parameter);
	}

	u8_t * const buffer = static_cast<u8_t *>(p_buffer);

	if (write_extented_type_when_true == false
		&& is_ietf_type(p_type) == true
		&& buffer_length >= eap_expanded_type_c::m_ietf_type_size*(index+1ul))
	{
		u8_t * const type_data =
			&(buffer[eap_expanded_type_c::m_ietf_type_size*index]);
		if (type_data == 0)
		{
			return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
		}

		*type_data = static_cast<u8_t>(p_type.get_vendor_type());
	}
	else if ((write_extented_type_when_true == true
				 || is_ietf_type(p_type) == false)
			 && buffer_length >= eap_header_base_c::get_expanded_type_field_length()*(index+1ul))
	{
		//  0                   1                   2                   3
		//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |     Type      |               Vendor-Id                       |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |                          Vendor-Type                          |
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		// |              Vendor data or other Type ...
		// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
		{
			u8_t * const type_data =
				&(buffer[eap_header_base_c::get_expanded_ietf_type_offset()
							+eap_header_base_c::get_expanded_type_field_length()*index]);
			if (type_data == 0)
			{
				return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
			}
			*type_data = static_cast<u8_t>(eap_type_expanded_type);
		}

		{
			u8_t * const vendor_id =
				&(buffer[eap_header_base_c::get_expanded_vendor_id_offset()
							+eap_header_base_c::get_expanded_type_field_length()*index]);
			if (vendor_id == 0)
			{
				return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
			}
			eap_status_e status = eap_write_u24_t_network_order(
				vendor_id,
				3ul*sizeof(u8_t),
				static_cast<u32_t>(p_type.get_vendor_id()));
			EAP_ASSERT_ALWAYS_TOOLS(am_tools, status == eap_status_ok);
		}

		{
			u8_t * const vendor_type =
				&(buffer[eap_header_base_c::get_expanded_vendor_type_offset()
							+eap_header_base_c::get_expanded_type_field_length()*index]);
			if (vendor_type == 0)
			{
				return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
			}
			eap_status_e status = eap_write_u32_t_network_order(
				vendor_type,
				sizeof(u32_t),
				p_type.get_vendor_type());
			EAP_ASSERT_ALWAYS_TOOLS(am_tools, status == eap_status_ok);
		}
	}
	else
	{
		return EAP_STATUS_RETURN(am_tools, eap_status_allocation_error);
	}

	return EAP_STATUS_RETURN(am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT i32_t eap_expanded_type_c::compare(const eap_expanded_type_c * const data) const
{
	if (*this == *data)
	{
		return 0;
	}
	else
	{
		if (get_vendor_id() < data->get_vendor_id()
			|| (get_vendor_id() == data->get_vendor_id()
				&& get_vendor_type() < data->get_vendor_type()))
		{
			 // (*this < *data)
			return -1;
		}
		else
		{
			// (*this > *data)
			return +1;
		}
	}
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_FUNC_EXPORT const eap_expanded_type_c &eap_static_expanded_type_c::get_type() const
{
	return *reinterpret_cast<const eap_expanded_type_c *>(this);
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------

EAP_C_FUNC_EXPORT u32_t convert_eap_type_to_u32_t(eap_type_value_e type)
{
	// NOTE, this returns only 8 least significant bits of vendor type.
	return static_cast<u32_t>(type.get_vendor_id() << sizeof(u8_t)*8ul
							  | (0xff & type.get_vendor_type()));
}

EAP_C_FUNC_EXPORT u64_t convert_eap_type_to_u64_t(eap_type_value_e type)
{
	return static_cast<u64_t>(type.get_vendor_id()) << sizeof(u32_t)*8ul
		| static_cast<u64_t>(type.get_vendor_type());
}

//--------------------------------------------------
//--------------------------------------------------
//--------------------------------------------------



// End.
