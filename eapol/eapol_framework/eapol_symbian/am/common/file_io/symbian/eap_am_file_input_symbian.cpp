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
* %version: 11.1.3 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 143 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include <stdio.h>

#include "eap_am_file_input_symbian.h"

//----------------------------------------------------------------------------------------------------

/**
 * The destructor of the eap_am_file_input_symbian_c class does nothing special.
 */
EAP_FUNC_EXPORT eap_am_file_input_symbian_c::~eap_am_file_input_symbian_c()
{
	file_close();

	delete m_input_buffer;
	m_input_buffer = 0;
}

//----------------------------------------------------------------------------------------------------

/**
 * The constructor of the eap_am_file_input_symbian_c does nothing special.
 */
EAP_FUNC_EXPORT eap_am_file_input_symbian_c::eap_am_file_input_symbian_c(
	abs_eap_am_tools_c * const tools)
: m_am_tools(tools)
, m_is_valid(false)
, m_input_buffer(0)
, m_input_buffer_offset(0ul)
{
	m_input_buffer = new TBuf8<EAP_AM_FILE_INPUT_BUFFER_SIZE>;
	if (m_input_buffer == 0)
	{
		return;
	}

	set_is_valid();
}

//----------------------------------------------------------------------------------------------------

/**
 * This function checks the file of name file_name exists.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_exists(const eap_variable_data_c * const file_name)
{
	eap_am_file_input_symbian_c file(m_am_tools);

	eap_status_e status = file.file_open(
		file_name,
		eap_file_io_direction_read);

	if (status == eap_status_ok)
	{
		(void)file.file_close();
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//----------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_delete(
		const eap_variable_data_c * const /* file_name */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//----------------------------------------------------------------------------------------------------

/**
 * This function copies the file source_file_name to file target_file_name.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_copy(
	const eap_variable_data_c * const target_file_name,
	const eap_variable_data_c * const source_file_name)
{
	eap_am_file_input_symbian_c read_file(m_am_tools);

	eap_status_e status = read_file.file_open(
		source_file_name,
		eap_file_io_direction_read);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: file_copy(): Cannot open source file  %s\n"),
			source_file_name->get_data(source_file_name->get_data_length())));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_am_file_input_symbian_c write_file(m_am_tools);

	status = write_file.file_open(
		target_file_name,
		eap_file_io_direction_write);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: file_copy(): Cannot open target file  %s\n"),
			target_file_name->get_data(target_file_name->get_data_length())));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	eap_variable_data_c buffer(m_am_tools);
	status = buffer.init(EAP_AM_FILE_INPUT_BUFFER_SIZE);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	bool end_of_file(false);

	while(end_of_file == false)
	{
		status = read_file.file_read(&buffer);
		if (status == eap_status_end_of_file)
		{
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("file_copy(): End of file.\n")));
			end_of_file = true;
		}
		else if (status != eap_status_ok)
		{
			eap_status_string_c status_string;
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: file_copy(): file_read(): status = %s\n"),
				status_string.get_status_string(status)));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("read data"),
			 buffer.get_data(),
			 buffer.get_data_length()));

		status = write_file.file_write(&buffer);
		if (status != eap_status_ok)
		{
			eap_status_string_c status_string;
			EAP_TRACE_DEBUG(
				m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: file_copy(): file_write(): status = %s\n"),
				status_string.get_status_string(status)));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	} // while()

	write_file.file_close();
	read_file.file_close();

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("file_copy(): OK\n")));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//----------------------------------------------------------------------------------------------------

/**
 * This function returns size of a file.
 */
EAP_FUNC_EXPORT u32_t eap_am_file_input_symbian_c::file_size()
{
	TInt aSize(0ul);

	TInt size_status = m_File.Size(aSize);

	if (size_status != KErrNone)
	{
		return 0ul;
	}

	return static_cast<u32_t>(aSize);
}

//----------------------------------------------------------------------------------------------------

/**
 * This function reads data from file.
 * Maximum size read is the buffer size.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_read(eap_variable_data_c * const buffer)
{
 	TPtr8 tmp(buffer->get_buffer(buffer->get_buffer_length()), buffer->get_buffer_length());
	
	TInt ReadStatus = m_File.Read(tmp);
	
	if (ReadStatus != KErrNone
		|| tmp.Length() == 0UL
		|| tmp.Ptr() == 0)
	{
		buffer->set_data_length(0ul);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_end_of_file);
	}
	else
	{
		buffer->set_data_length(tmp.Length());
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
}

//----------------------------------------------------------------------------------------------------

/**
 * This function write data to a file.
 * Maximum size write is the buffer size.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_write(const eap_variable_data_c * const buffer)
{
 	TPtr8 tmp(buffer->get_data(), buffer->get_data_length());
	
	TInt WriteStatus = m_File.Write(tmp);
	
	if (WriteStatus != KErrNone)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_file_write_failed);
	}

	WriteStatus = m_File.Flush();
	
	if (WriteStatus != KErrNone)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_file_write_failed);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//----------------------------------------------------------------------------------------------------

const u32_t EAP_MAX_FILENAME_LENGTH = 128;

/**
 * This function opens file of name file_name.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_open(
	const eap_variable_data_c * const file_name,
	const eap_file_io_direction_e dir)
{
	TBuf8<EAP_MAX_FILENAME_LENGTH> tmpFilename((TUint8 *)file_name->get_data(file_name->get_data_length()));
	tmpFilename.SetLength(file_name->get_data_length());

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("Configure file"), 
		 tmpFilename.PtrZ(), 
		 tmpFilename.Length()));

	TBuf<EAP_MAX_FILENAME_LENGTH> filename;
	filename.Copy(tmpFilename);

	EAP_TRACE_DATA_DEBUG(
		m_am_tools, 
		TRACE_FLAGS_DEFAULT, 
		(EAPL("Configure file"), 
		 filename.PtrZ(), 
		 filename.Size()));

	TInt result = m_file_session.Connect();	
	if (result != KErrNone)
	{
		EAP_TRACE_ERROR(m_am_tools,
				TRACE_FLAGS_DEFAULT,
				(EAPL("ERROR: configuration file %s not found, error %d\n"),
				 reinterpret_cast<char *>(file_name->get_data(file_name->get_data_length())),
				 result));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_file_does_not_exist);
	}
	
	TUint aFileMode = EFileRead | EFileShareAny;
	if (dir == eap_file_io_direction_write)
	{
		aFileMode = EFileWrite;
	}

	TInt err = m_File.Open(m_file_session, filename, aFileMode);
	if (err != KErrNone)
	{
		if (aFileMode == EFileWrite)
		{
			// Try create a new file.
			err = m_File.Create(m_file_session, filename, aFileMode);
		}
		
		if (err != KErrNone)
		{
			EAP_TRACE_ERROR(m_am_tools,
					TRACE_FLAGS_DEFAULT,
					(EAPL("ERROR: configuration file %s not found, mode %d, error %d\n"),
					 reinterpret_cast<char *>(file_name->get_data(file_name->get_data_length())),
					 aFileMode,
					 err));
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_file_does_not_exist);
		}
	}

	m_input_buffer_offset = 0ul;

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//----------------------------------------------------------------------------------------------------

/**
 * The function closes the file.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_close()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);

	m_File.Close();
	m_file_session.Close();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//----------------------------------------------------------------------------------------------------

/**
 * This function reads n bytes from file to buffer.
 */
eap_status_e eap_am_file_input_symbian_c::file_read_buffer(
	eap_variable_data_c * const buffer,
	const u32_t required_bytes)
{
	u32_t read_bytes(0ul);

	eap_status_e status = buffer->set_data_length(0ul);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	bool file_end(false);

	while(file_end == false
		&& read_bytes < required_bytes)
	{
		if (m_input_buffer->Length() == m_input_buffer_offset)
		{
			TInt ReadStatus = m_File.Read(*m_input_buffer, EAP_AM_FILE_INPUT_BUFFER_SIZE);
			if (ReadStatus != KErrNone
				|| m_input_buffer->Length() == 0UL
				|| m_input_buffer->Ptr() == 0)
			{
				file_end = true;
			}

			m_input_buffer_offset = 0ul;
		}

		const u8_t * const character = m_input_buffer->Ptr() + m_input_buffer_offset;
		if (character == 0)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_end_of_file);
		}

		u32_t copied_bytes = required_bytes - read_bytes;
		if (copied_bytes > (m_input_buffer->Length() - m_input_buffer_offset))
		{
			copied_bytes = (m_input_buffer->Length() - m_input_buffer_offset);
		}

		status = buffer->add_data(character, copied_bytes);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		read_bytes += copied_bytes;
		m_input_buffer_offset += copied_bytes;

	} // while()

	if (file_end == true)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_end_of_file);
	}
	else
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
	}
}

//----------------------------------------------------------------------------------------------------

/**
 * This function reads line from file.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_read_line(
	eap_variable_data_c * const line)
{
	if (line == 0
		|| line->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	line->set_data_length(0ul);

	eap_variable_data_c buffer(m_am_tools);

	eap_status_e file_status(eap_status_ok);

	while (file_status == eap_status_ok)
	{
		file_status = file_read_buffer(
			&buffer,
			sizeof(u8_t));
		if (file_status != eap_status_ok
			&& file_status != eap_status_end_of_file)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, file_status);
		}

		if (buffer.get_data_length() < sizeof(u8_t))
		{
			file_status = EAP_STATUS_RETURN(m_am_tools, eap_status_end_of_file);
			break;
		}

		const u8_t * const character = buffer.get_data(sizeof(u8_t));

		if (character == 0
			|| *character == '\n')
		{
			// This is the end of the line.
			break;
		}

		if (*character != '\r') // Windows files inludes these.
		{
			eap_status_e status = line->add_data(character, sizeof(*character));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}

	} // while()

	{
		eap_status_e add_status = line->add_end_null();
		if (add_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, add_status);
		}
	}

	// Note this should return the final file_status.
	return EAP_STATUS_RETURN(m_am_tools, file_status);
}

//----------------------------------------------------------------------------------------------------

/**
 * This function reads word from file.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::file_read_word(eap_variable_data_c * const word)
{
	if (word == 0
		|| word->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	word->set_data_length(0ul);

	eap_variable_data_c buffer(m_am_tools);

	eap_status_e file_status(eap_status_ok);

	while (file_status == eap_status_ok)
	{
		file_status = file_read_buffer(
			&buffer,
			sizeof(u8_t));
		if (file_status != eap_status_ok
			&& file_status != eap_status_end_of_file)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, file_status);
		}

		if (buffer.get_data_length() < sizeof(u8_t))
		{
			file_status = EAP_STATUS_RETURN(m_am_tools, eap_status_end_of_file);
			break;
		}

		const u8_t * character = buffer.get_data(sizeof(u8_t));

		if (character == 0
			|| m_am_tools->isspace(*character)
			|| *character == ',')
		{
			break;
		}
		else if (*character == '#')
		{
			while (file_status == eap_status_ok)
			{
				file_status = file_read_buffer(
					&buffer,
					sizeof(u8_t));
				if (file_status != eap_status_ok
					&& file_status != eap_status_end_of_file)
				{
					EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
					return EAP_STATUS_RETURN(m_am_tools, file_status);
				}

				character = buffer.get_data(sizeof(u8_t));

				if (character == 0
					|| *character == '\n')
				{
					break;
				}
			}
		}
		else
		{
			eap_status_e status = word->add_data(character, sizeof(*character));
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
	} // while()


	{
		eap_status_e add_status = word->add_end_null();
		if (add_status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
			return EAP_STATUS_RETURN(m_am_tools, add_status);
		}
	}


	// Note this should return the final file_status.
	return EAP_STATUS_RETURN(m_am_tools, file_status);
}

//----------------------------------------------------------------------------------------------------

/**
 * The set_is_valid() function sets the state of the object valid.
 * The creator of this object calls this function after it is initialized. 
 */
void eap_am_file_input_symbian_c::set_is_valid()
{
	m_is_valid = true;
}

//----------------------------------------------------------------------------------------------------

/**
 * Object must indicate it's validity.
 * If object initialization fails this function must return false.
 * @return This function returns the validity of this object.
 */
EAP_FUNC_EXPORT bool eap_am_file_input_symbian_c::get_is_valid()
{
	return m_is_valid;
}

//----------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::directory_open(
	const eap_variable_data_c * const /* directory_name */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//----------------------------------------------------------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::directory_read(
	eap_array_c<abs_eap_file_stat_c> * const /* directory_list */)
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//----------------------------------------------------------------------------------------------------

/**
 * This function closes the directory.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_file_input_symbian_c::directory_close()
{
	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

//----------------------------------------------------------------------------------------------------

abs_eap_am_file_input_c * abs_eap_am_file_input_c::new_abs_eap_am_file_input_c(
	abs_eap_am_tools_c * const tools)
{
	abs_eap_am_file_input_c * const file_input = new eap_am_file_input_symbian_c(tools);

	if (file_input == 0
		|| file_input->get_is_valid() == false)
	{
		delete file_input;
		(void) EAP_STATUS_RETURN(tools, eap_status_allocation_error);
		return 0;
	}

	return file_input;
}

//----------------------------------------------------------------------------------------------------

// End.
