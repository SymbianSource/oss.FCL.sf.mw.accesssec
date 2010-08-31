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
	#define EAP_FILE_NUMBER_ENUM 10 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"
#include "eap_am_memory_store.h"
#include "eap_crypto_api.h"
#include "eap_automatic_variable.h"

//#if !defined(NO_EAP_AM_MEMORY_STORE)

const u32_t EAP_MEMORY_STORE_RC4_KEY_STREAM_DISCARD_LENGTH = 256ul;

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_am_memory_store_c::~eap_am_memory_store_c()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_memory_store_c::~eap_am_memory_store_c(): this = 0x%08x.\n"),
		this));
}

//-------------------------------------------------------------------

#if defined(_WIN32) && !defined(__GNUC__)
	#pragma warning( disable : 4355 ) // 'this' : used in base member initializer list
#endif

EAP_FUNC_EXPORT eap_am_memory_store_c::eap_am_memory_store_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_store_new(tools, this)
	, m_timer_id_counter(0ul)
	, m_is_valid(false)
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_memory_store_c::eap_am_memory_store_c(): this = 0x%08x.\n"),
		this));

	set_is_valid();
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_memory_store_c::shutdown()
{
	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_memory_store_c::shutdown(): begins this = 0x%08x.\n"),
		this));

	return eap_status_ok;

}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT void eap_am_memory_store_c::set_is_valid()
{
	m_is_valid = true;
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT bool eap_am_memory_store_c::get_is_valid()
{
	return m_is_valid;
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_memory_store_c::add_data(
	const eap_variable_data_c * const key,
	const eap_tlv_message_data_c * const data,
	const u32_t timeout)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_memory_store_c::add_data(): data = 0x%08x.\n"),
		data));

	if (key == 0
		|| data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_memory_store_tlv_data_c * const tlv_data = new eap_am_memory_store_tlv_data_c(m_am_tools);
	if (tlv_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_automatic_variable_c<eap_am_memory_store_tlv_data_c> automatic_tlv_data(
		m_am_tools,
		tlv_data);

	eap_status_e status = tlv_data->copy_message_data(
		data,
		++m_timer_id_counter);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	eap_variable_data_c crypted_key(m_am_tools);
	status = crypted_key.set_copy_of_buffer(key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// This encryption hides the plain text data.
		// This is lame hidden operation of credentials.
		// @{ The key should be crypted lamely too.}
		crypto_rc4_c rc4(m_am_tools);
		if (rc4.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		status = rc4.set_key(key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = rc4.discard_stream(EAP_MEMORY_STORE_RC4_KEY_STREAM_DISCARD_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = rc4.encrypt_data(
			crypted_key.get_data(),
			crypted_key.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		status = rc4.set_key(key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = rc4.discard_stream(EAP_MEMORY_STORE_RC4_KEY_STREAM_DISCARD_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		status = rc4.encrypt_data(
			tlv_data->get_message_data(),
			tlv_data->get_message_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("eap_am_memory_store_c::add_data(): timeout %d, timer id %d, data = 0x%08x.\n"),
		 timeout,
		 tlv_data->get_timer_id(),
		 data));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::add_data():         key"),
		 key->get_data(),
		 key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::add_data(): crypted key"),
		 crypted_key.get_data(),
		 crypted_key.get_data_length()));
	
	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::add_data(): plain text data"),
		 data->get_message_data(),
		 data->get_message_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::add_data():     hidden data"),
		 tlv_data->get_message_data(),
		 tlv_data->get_message_data_length()));

	status = m_store_new.add_handler(&crypted_key, tlv_data);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	automatic_tlv_data.do_not_free_variable();

	if (timeout != 0ul)
	{
		eap_variable_data_c * const copy_key = key->copy();
		if (copy_key == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = m_am_tools->am_set_timer(
			this,
			tlv_data->get_timer_id(),
			copy_key,
			timeout);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_memory_store_c::get_data(
	const eap_variable_data_c * const key,
	eap_tlv_message_data_c * const data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	if (key == 0
		|| data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_variable_data_c crypted_key(m_am_tools);
	eap_status_e status = crypted_key.set_copy_of_buffer(key);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	{
		// This encryption restores lamely hidden key of data.
		crypto_rc4_c rc4(m_am_tools);
		if (rc4.get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}
		
		status = rc4.set_key(key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = rc4.discard_stream(EAP_MEMORY_STORE_RC4_KEY_STREAM_DISCARD_LENGTH);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
		
		status = rc4.encrypt_data(
			crypted_key.get_data(),
			crypted_key.get_data_length());
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::get_data(): key"),
		 key->get_data(),
		 key->get_data_length()));

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::get_data(): crypted key"),
		 crypted_key.get_data(),
		 crypted_key.get_data_length()));
	
	eap_am_memory_store_tlv_data_c * const tlv_data = m_store_new.get_handler(&crypted_key);

	if (tlv_data == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
	}
	else
	{
		status = data->copy_message_data(
			tlv_data->get_message_data_length(),
			tlv_data->get_message_data());
		
		{
			// This encryption restores lamely hidden plain text data.
			crypto_rc4_c rc4(m_am_tools);
			if (rc4.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
			
			status = rc4.set_key(key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			status = rc4.discard_stream(EAP_MEMORY_STORE_RC4_KEY_STREAM_DISCARD_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			
			status = rc4.decrypt_data(
				data->get_message_data(),
				data->get_message_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_am_memory_store_c::get_data(): timer id %d, data = 0x%08x.\n"),
				 tlv_data->get_timer_id(),
				 data));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_memory_store_c::get_data():     hidden data"),
				 tlv_data->get_message_data(),
				 tlv_data->get_message_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_memory_store_c::get_data(): plain text data"),
				 data->get_message_data(),
				 data->get_message_data_length()));

		}

		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
}

//-------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_memory_store_c::remove_data(
	const eap_variable_data_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::remove_data(): key"),
		 key->get_data(),
		 key->get_data_length()));

	eap_status_e status(eap_status_ok);

	{
		eap_variable_data_c crypted_key(m_am_tools);
		eap_status_e status = crypted_key.set_copy_of_buffer(key);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		{
			// This encryption restores lamely hidden key of data.
			crypto_rc4_c rc4(m_am_tools);
			if (rc4.get_is_valid() == false)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
			}
		
			status = rc4.set_key(key);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		
			status = rc4.discard_stream(EAP_MEMORY_STORE_RC4_KEY_STREAM_DISCARD_LENGTH);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		
			status = rc4.encrypt_data(
				crypted_key.get_data(),
				crypted_key.get_data_length());
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_memory_store_c::remove_data(): crypted key"),
			 crypted_key.get_data(),
			 crypted_key.get_data_length()));
		
		eap_am_memory_store_tlv_data_c * const data = m_store_new.get_handler(&crypted_key);
		if (data != 0)
		{
			EAP_TRACE_DEBUG(
				m_am_tools, 
				TRACE_FLAGS_DEFAULT, 
				(EAPL("eap_am_memory_store_c::remove_data(): timer id %d, data = 0x%08x.\n"),
				 data->get_timer_id(),
				 data));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_memory_store_c::remove_data(): key"),
				 key->get_data(),
				 key->get_data_length()));

			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("eap_am_memory_store_c::remove_data():     hidden data"),
				 data->get_message_data(),
				 data->get_message_data_length()));

			(void) m_am_tools->am_cancel_timer(
				this,
				data->get_timer_id());

			status = m_store_new.remove_handler(&crypted_key, true);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		else
		{
			EAP_TRACE_DATA_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("WARNING: eap_am_memory_store_c::remove_data(): key not found"),
				 crypted_key.get_data(),
				 crypted_key.get_data_length()));
		}
	}

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::remove_data(): returns %d\n"),
		status));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//-------------------------------------------------------------------

/**
 * Function timer_expired() is called after the timer is elapsed.
 * @param id and data are set by caller of abs_eap_am_tools::set_timer() function.
 * @param id could be used to separate different timer events.
 * @param data could be pointer to any data that is needed in timer processing.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_memory_store_c::timer_expired(
	const u32_t id, void *data)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::timer_expired(): id %d, data 0x%08x\n"),
		 id,
		 data));

	if (data != 0)
	{
		eap_variable_data_c * const key = reinterpret_cast<eap_variable_data_c *>(data);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_memory_store_c::timer_expired(): key"),
			 key->get_data(),
			 key->get_data_length()));

		eap_am_memory_store_tlv_data_c * const tlv_data = m_store_new.get_handler(key);
		if (tlv_data != 0)
		{
			if (id == tlv_data->get_timer_id())
			{
				eap_status_e status = remove_data(key);

				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
			else
			{
				EAP_TRACE_DEBUG(
					m_am_tools,
					TRACE_FLAGS_ERROR,
					(EAPL("eap_am_memory_store_c::timer_expired(): id %d != tlv_data->id %d, tlv_data 0x%08x\n"),
					 id,
					 tlv_data->get_timer_id(),
					 tlv_data));
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, eap_status_not_found);
			}
		}
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-------------------------------------------------------------------

/**
 * This function is called when timer event is deleted.
 * Initialiser of the data must delete the data.
 * Only the initializer knows the real type of data.
 * @param id could be used to separate different timer events.
 * @param data could be pointer to any data that is needed in timer processing.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_memory_store_c::timer_delete_data(
	const u32_t id, void *data)
{
	EAP_UNREFERENCED_PARAMETER(id);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_memory_store_c::timer_delete_data(): id %d, data 0x%08x\n"),
		 id,
		 data));

	if (data != 0)
	{
		eap_variable_data_c * const key = reinterpret_cast<eap_variable_data_c *>(data);

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("eap_am_memory_store_c::timer_delete_data(): key"),
			 key->get_data(),
			 key->get_data_length()));

		delete key;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//-------------------------------------------------------------------

//#endif //#if !defined(NO_EAP_AM_MEMORY_STORE)

// End.
