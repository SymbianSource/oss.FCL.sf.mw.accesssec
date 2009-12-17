/*
* Copyright (c) 2001-2005 Nokia Corporation and/or its subsidiary(-ies).
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


#if defined(_DEBUG) || defined(DEBUG)

#include "eap_am_trace_symbian.h"

const TInt KMaxBufferSize = 256;

u8_t octet_to_ascii(i32_t octet)
{
	if (0 <= octet && octet <= 9)
	{
		return static_cast<u8_t>('0' + octet);
	}
	else if (10 <= octet && octet <= 16)
	{
		return static_cast<u8_t>('a' + (octet-10u));
	}
	else
	{
		return 0;
	}
}

void formatted_print(eap_format_string format, ...)
{
	EAP_UNREFERENCED_PARAMETER(format);

#if defined(USE_EAP_TRACE) || defined(USE_EAP_TRACE_ALWAYS)

	HBufC8* args_buf = NULL;
	HBufC8* format_buf = NULL;
	HBufC8* trace_buf = NULL;
	HBufC16* trace_buf_16 = NULL;
	
	TRAPD(error, 
		args_buf= HBufC8::NewL(KMaxBufferSize);
		format_buf= HBufC8::NewL(KMaxBufferSize);
		trace_buf= HBufC8::NewL(KMaxBufferSize);
		trace_buf_16= HBufC16::NewL(KMaxBufferSize); );
		
	if(error != KErrNone)
	{
		// Not enough memory.
		RDebug::Print(_L("formatted_print: ERROR - Not enough Memory!\n"));
		
		delete args_buf;
		delete format_buf;
		delete trace_buf;
		delete trace_buf_16;
				
		return;
	}
	
	TPtr8 m_args_buf = args_buf->Des();
	TPtr8 m_format_buf = format_buf->Des();
	TPtr8 m_trace_buf = trace_buf->Des();
	TPtr16 m_trace_buf_16 = trace_buf_16->Des();

	VA_LIST args;
	VA_START(args, format);
	m_format_buf.Copy((const TUint8 *)format);
	
	m_args_buf.FormatList(m_format_buf, args);
	m_trace_buf.Append(m_args_buf);			
	VA_END(args);

#if defined(USE_EAP_HARDWARE_TRACE)

	{
		#if !defined(USE_EAP_HARDWARE_TRACE_RAW_PRINT)
		{
			TInt length = m_trace_buf.Length();
			if (length >= 2ul)
			{
				--length;
				const TUint8 *last_char = m_trace_buf.Ptr() + length;

				if (last_char != 0
					&& *last_char == '\n')
				{
					// This removes the ending new line character.
					// formatted_print() will write new line automatically.
					m_trace_buf.SetLength(length);
				}
			}
		}
		#endif //#if !defined(USE_EAP_HARDWARE_TRACE_RAW_PRINT)
		
		m_trace_buf_16.Copy(m_trace_buf);

		#if defined(USE_EAP_HARDWARE_TRACE_RAW_PRINT)
			RDebug::RawPrint(m_trace_buf_16);
		#else
			formatted_print(_L("%S"), &m_trace_buf_16);
		#endif //#if defined(USE_EAP_HARDWARE_TRACE_RAW_PRINT)
	}

#endif //#if defined(USE_EAP_HARDWARE_TRACE)

	delete args_buf;
	delete format_buf;
	delete trace_buf;
	delete trace_buf_16;

#endif //#if defined(USE_EAP_TRACE) || defined(USE_EAP_TRACE_ALWAYS)

}


void trace_data(
	eap_const_string prefix,
	const void * const p_data,
	const u32_t data_length)
{

	u8_t* m_tmp_buffer = NULL;	
	u8_t* m_tmp_ascii_buffer = NULL;
		
	m_tmp_buffer = new u8_t[KMaxBufferSize];	
	m_tmp_ascii_buffer = new u8_t[KMaxBufferSize];
		
	if( m_tmp_buffer == NULL || m_tmp_ascii_buffer == NULL)
	{
		// Not enough memory.
		RDebug::Print(_L("trace_data: ERROR - Not enough Memory!\n"));
		
		delete [] m_tmp_buffer;
		delete [] m_tmp_ascii_buffer;
		
		return;
	}

	u8_t *cursor = m_tmp_buffer;
	u8_t *cursor_ascii = m_tmp_ascii_buffer;
	
	const u8_t *data = reinterpret_cast<const u8_t *>(p_data);
	u32_t ind;
	bool must_print = false;
	u32_t data_start = 0u;

	const u32_t EAP_DATA_TRACE_BYTE_GROUP_SIZE = 1;
	u32_t byte_group_size = EAP_DATA_TRACE_BYTE_GROUP_SIZE;

#if !defined(USE_EAP_DEBUG_TRACE)
	// This does not trace the pointer of the data.
	formatted_print(
		"%s: data: %d (0x%x) bytes\n",
		prefix,
		data_length,
		data_length);
#else
	formatted_print(
		"%s: data 0x%08x: %d (0x%x) bytes\n",
		prefix,
		p_data,
		data_length,
		data_length);
#endif

	if (p_data == 0)
	{
		delete [] m_tmp_buffer;
		delete [] m_tmp_ascii_buffer;
	
		return;
	}

	for (ind = 0u; ind < data_length; ind++)
	{
		if ((cursor-m_tmp_buffer)+5u >= KMaxBufferSize)
		{
			must_print = true;
			formatted_print(
				"ERROR: eap_am_tools_c::trace_data local buffer (%d bytes) too small.\n",
				KMaxBufferSize);
			break;
		}


		if (ind > 0u
			&& (ind % 16) == 0)
		{
			*cursor++ = 0;
			*cursor_ascii++ = 0;

			formatted_print(
				"%s: 0x%04x: %-48s |%-16s|\n",
				prefix,
				data_start,
				m_tmp_buffer,
				m_tmp_ascii_buffer);

			cursor = m_tmp_buffer;
			cursor_ascii = m_tmp_ascii_buffer;
			must_print = false;
			data_start = ind;
		}

		*cursor_ascii++ = (*data >= 32 && *data < 128) ? *data : '.';

		*cursor++ = octet_to_ascii(((*data) & 0xf0) >> 4);
		*cursor++ = octet_to_ascii(((*data) & 0x0f));
		data++;

		if (ind > 0u
			&& ((ind+1) % byte_group_size) == 0
			|| byte_group_size == 1ul)
		{
			*cursor++ = ' ';
		}

		must_print = true;
	}

	if (must_print == true)
	{
		*cursor++ = 0;
		*cursor_ascii = 0;
		formatted_print(
			"%s: 0x%04x: %-48s |%-16s|\n",
			prefix,
			data_start,
			m_tmp_buffer,
			m_tmp_ascii_buffer);
	}
	
	delete [] m_tmp_buffer;
	delete [] m_tmp_ascii_buffer;
}

#endif

// End of file
