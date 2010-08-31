/*
* Copyright (c) 2001-2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description:  Some integer order functions for all platforms.
*
*/

/*
* %version: 13.1.2 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 41 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



/** @file */

#include "eap_tools.h"

//-------------------------------------------------------------------

EAP_C_FUNC_EXPORT u16_t eap_htons(const u16_t value)
{
	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		return(static_cast<u16_t>((value >> (sizeof(u8_t)*8u))
					| (value << (sizeof(u8_t)*8u))));
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		return value;
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}

EAP_C_FUNC_EXPORT u32_t eap_htonl(const u32_t value)
{
	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		return(static_cast<u32_t>((value & 0xFF) << 24)
					| ((value & 0xFF00) << 8)
					| ((value & 0xFF0000) >> 8)
					| ((value & 0xFF000000) >> 24));
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		return value;
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}

EAP_C_FUNC_EXPORT u64_t eap_htonll(const u64_t value)
{

	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		#if defined(__SYMBIAN32__)
			u32_t *val = reinterpret_cast<u32_t *>(const_cast<u64_t *>(&value));
			u64_t out_buf;
			u32_t *out = reinterpret_cast<u32_t *>(&out_buf);

			out[0] = eap_htonl(val[1]);
			out[1] = eap_htonl(val[0]);

			return out_buf;
		#else
			return(static_cast<u64_t>((value & 0xFF) << 56)
						| ((value & 0xFF00) << 40)
						| ((value & 0xFF0000) << 24)
						| ((value & 0xFF000000) << 8)
						| (((value >> 32) & 0xFF) << 24)
						| (((value >> 32) & 0xFF00) << 8)
						| (((value >> 32) & 0xFF0000) >> 8)
						| (((value >> 32) & 0xFF000000) >> 24));
		#endif
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		return value;
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}

EAP_C_FUNC_EXPORT u16_t eap_host_to_little_endian_short(const u16_t value)
{
	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		return value;
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		return(static_cast<u16_t>((value & 0xFF) << 8)
					| ((value & 0xFF00) >> 8));
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}

EAP_C_FUNC_EXPORT u32_t eap_host_to_little_endian_long(const u32_t value)
{
	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		return value;
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		return(static_cast<u32_t>((value & 0xFF) << 24)
					| ((value & 0xFF00) << 8)
					| ((value & 0xFF0000) >> 8)
					| ((value & 0xFF000000) >> 24));
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}

EAP_C_FUNC_EXPORT u64_t eap_host_to_little_endian_long_long(const u64_t value)
{
	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		return value;
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		#if defined(__SYMBIAN32__)
			u32_t *val = reinterpret_cast<u32_t *>(const_cast<u64_t *>(&value));
			u64_t out_buf;
			u32_t *out = reinterpret_cast<u32_t *>(&out_buf);

			out[0] = eap_host_to_little_endian_long(val[1]);
			out[1] = eap_host_to_little_endian_long(val[0]);

			return out_buf;
		#else
			return(static_cast<u64_t>((value & 0xFF) << 56)
						| ((value & 0xFF00) << 40)
						| ((value & 0xFF0000) << 24)
						| ((value & 0xFF000000) << 8)
						| (((value >> 32) & 0xFF) << 24)
						| (((value >> 32) & 0xFF00) << 8)
						| (((value >> 32) & 0xFF0000) >> 8)
						| (((value >> 32) & 0xFF000000) >> 24));
		#endif
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif
}

//-------------------------------------------------------------------

EAP_C_FUNC_EXPORT eap_status_e eap_write_u16_t_little_endian_order(
	void * const p_data,
	const u32_t data_length,
	const u16_t value)
{
	if (data_length < sizeof(u16_t)
		|| p_data == 0)
	{
		return eap_status_allocation_error;
	}

	u8_t * const data = static_cast<u8_t *>(p_data);

	data[0] = static_cast<u8_t>((value) & 0xff);
	data[1] = static_cast<u8_t>((value >> 8) & 0xff);

	return eap_status_ok;
}

EAP_C_FUNC_EXPORT eap_status_e eap_write_u32_t_little_endian_order(
	void * const p_data,
	const u32_t data_length,
	const u32_t value)
{
	if (data_length < sizeof(u32_t)
		|| p_data == 0)
	{
		return eap_status_allocation_error;
	}

	u8_t * const data = static_cast<u8_t *>(p_data);

	data[0] = static_cast<u8_t>((value) & 0xff);
	data[1] = static_cast<u8_t>((value >> 8) & 0xff);
	data[2] = static_cast<u8_t>((value >> 16) & 0xff);
	data[3] = static_cast<u8_t>((value >> 24) & 0xff);

	return eap_status_ok;
}


EAP_C_FUNC_EXPORT eap_status_e eap_write_u64_t_little_endian_order(
	void * const p_data,
	const u32_t data_length,
	const u64_t value)
{
	if (data_length < sizeof(u64_t)
		|| p_data == 0)
	{
		return eap_status_allocation_error;
	}

	// This is used because Symbian does not have 64 bit shift operation.
	u8_t * const data = static_cast<u8_t *>(p_data);

	const u32_t * const outvalue = reinterpret_cast<const u32_t *>(&value);

	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		const u32_t least_significant_u32_t_index = 0;
		const u32_t most_significant_u32_t_index = 1;
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		const u32_t most_significant_u32_t_index = 0;
		const u32_t least_significant_u32_t_index = 1;
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif

	eap_status_e status = eap_write_u32_t_little_endian_order(
		data,
		sizeof(u32_t),
		outvalue[least_significant_u32_t_index]);
	if (status != eap_status_ok)
	{
		return status;
	}

	status = eap_write_u32_t_little_endian_order(
		data+sizeof(u32_t),
		sizeof(u32_t),
		outvalue[most_significant_u32_t_index]);
	if (status != eap_status_ok)
	{
		return status;
	}

	return eap_status_ok;
}


EAP_C_FUNC_EXPORT u16_t eap_read_u16_t_little_endian_order(
	const void * const p_data,
	const u32_t data_length)
{
	if (data_length < sizeof(u16_t)
		|| p_data == 0)
	{
		return 0ul;
	}

	const u8_t * const data = static_cast<const u8_t *>(p_data);

	return(static_cast<u16_t>(
		(static_cast<u16_t>(data[0])
		| static_cast<u16_t>(data[1]) << 8)));
}

EAP_C_FUNC_EXPORT u32_t eap_read_u32_t_little_endian_order(
	const void * const p_data,
	const u32_t data_length)
{
	if (data_length < sizeof(u32_t)
		|| p_data == 0)
	{
		return 0ul;
	}

	const u8_t * const data = static_cast<const u8_t *>(p_data);

	return(static_cast<u32_t>(
		static_cast<u32_t>(data[0])
		| (static_cast<u32_t>(data[1]) << 8)
		| (static_cast<u32_t>(data[2]) << 16)
		| (static_cast<u32_t>(data[3]) << 24)));
}

EAP_C_FUNC_EXPORT u64_t eap_read_u64_t_little_endian_order(
	const void * const p_data,
	const u32_t data_length)
{
	if (data_length < sizeof(u64_t)
		|| p_data == 0)
	{
		return 0ul;
	}

	union
	{
		u64_t q;
		u64_struct w;
	} v;

	const u8_t *data = static_cast<const u8_t *>(p_data);

	v.w.low = eap_read_u32_t_little_endian_order(data,sizeof(u32_t));
	data += sizeof(u32_t);
	v.w.high = eap_read_u32_t_little_endian_order(data,sizeof(u32_t));

	return v.q;
}


EAP_C_FUNC_EXPORT u16_t eap_read_u16_t_network_order(
	const void * const p_data,
	const u32_t data_length)
{
	if (data_length < sizeof(u16_t)
		|| p_data == 0)
	{
		return 0ul;
	}

	const u8_t * const data = static_cast<const u8_t *>(p_data);

	return(static_cast<u16_t>(
		(static_cast<u16_t>(data[0]) << 8)
		| static_cast<u16_t>(data[1])));
}

EAP_C_FUNC_EXPORT u32_t eap_read_u24_t_network_order(
	const void * const p_data,
	const u32_t data_length)
{
	if (data_length < sizeof(u8_t)*3ul
		|| p_data == 0)
	{
		return 0ul;
	}

	const u8_t * const data = static_cast<const u8_t *>(p_data);

	return(static_cast<u32_t>(
		(static_cast<u32_t>(data[0]) << 16)
		| (static_cast<u32_t>(data[1]) << 8)
		| static_cast<u32_t>(data[2])));
}

EAP_C_FUNC_EXPORT u32_t eap_read_u32_t_network_order(
	const void * const p_data,
	const u32_t data_length)
{
	if (data_length < sizeof(u32_t)
		|| p_data == 0)
	{
		return 0ul;
	}

	const u8_t * const data = static_cast<const u8_t *>(p_data);

	return(static_cast<u32_t>(
		(static_cast<u32_t>(data[0]) << 24)
		| (static_cast<u32_t>(data[1]) << 16)
		| (static_cast<u32_t>(data[2]) << 8)
		| static_cast<u32_t>(data[3])));
}


/* The following function is problematic for ARM Linux. 
   There is now linux_gnu code which _should_ work also
   with other architectures. It does not use 64 bit shift.
*/
EAP_C_FUNC_EXPORT u64_t eap_read_u64_t_network_order(
	const void * const p_data,
	const u32_t data_length)
{
	if (data_length < sizeof(u64_t)
		|| p_data == 0)
	{
		return 0ul;
	}

	union
	{
		u64_t q;
		u64_struct w;
	} v;

	const u8_t *data = static_cast<const u8_t *>(p_data);

	v.w.high = eap_read_u32_t_network_order(data,sizeof(u32_t));
	data += sizeof(u32_t);
	v.w.low = eap_read_u32_t_network_order(data,sizeof(u32_t));

	return v.q;
}

//-------------------------------------------------------------------

EAP_C_FUNC_EXPORT eap_status_e eap_write_u16_t_network_order(
	void * const p_data,
	const u32_t data_length,
	const u16_t value)
{
	if (data_length < sizeof(u16_t)
		|| p_data == 0)
	{
		return eap_status_allocation_error;
	}

	u8_t * const data = static_cast<u8_t *>(p_data);

	data[0] = static_cast<u8_t>((value >> 8) & 0xff);
	data[1] = static_cast<u8_t>((value) & 0xff);

	return eap_status_ok;
}

EAP_C_FUNC_EXPORT eap_status_e eap_write_u24_t_network_order(
	void * const p_data,
	const u32_t data_length,
	const u32_t value)
{
	if (data_length < 3ul*sizeof(u8_t)
		|| p_data == 0)
	{
		return eap_status_allocation_error;
	}

	u8_t * const data = static_cast<u8_t *>(p_data);

	data[0] = static_cast<u8_t>((value >> 16) & 0xff);
	data[1] = static_cast<u8_t>((value >> 8) & 0xff);
	data[2] = static_cast<u8_t>((value) & 0xff);

	return eap_status_ok;
}

EAP_C_FUNC_EXPORT eap_status_e eap_write_u32_t_network_order(
	void * const p_data,
	const u32_t data_length,
	const u32_t value)
{
	if (data_length < sizeof(u32_t)
		|| p_data == 0)
	{
		return eap_status_allocation_error;
	}

	u8_t * const data = static_cast<u8_t *>(p_data);

	data[0] = static_cast<u8_t>((value >> 24) & 0xff);
	data[1] = static_cast<u8_t>((value >> 16) & 0xff);
	data[2] = static_cast<u8_t>((value >> 8) & 0xff);
	data[3] = static_cast<u8_t>((value) & 0xff);

	return eap_status_ok;
}

EAP_C_FUNC_EXPORT eap_status_e eap_write_u64_t_network_order(
	void * const p_data,
	const u32_t data_length,
	const u64_t value)
{
	if (data_length < sizeof(u64_t)
		|| p_data == 0)
	{
		return eap_status_allocation_error;
	}

	// This is used because Symbian does not have 64 bit shift operation.
	u8_t * const data = static_cast<u8_t *>(p_data);

	const u32_t * const outvalue = reinterpret_cast<const u32_t *>(&value);

	#if defined(EAP_LITTLE_ENDIAN) /// byte 0 is least significant (i386)
		const u32_t least_significant_u32_t_index = 0;
		const u32_t most_significant_u32_t_index = 1;
	#elif defined(EAP_BIG_ENDIAN) /// byte 0 is most significant (mc68k)
		const u32_t most_significant_u32_t_index = 0;
		const u32_t least_significant_u32_t_index = 1;
	#else
		#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
				or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
	#endif

	eap_status_e status = eap_write_u32_t_network_order(
		data,
		sizeof(u32_t),
		outvalue[most_significant_u32_t_index]);
	if (status != eap_status_ok)
	{
		return status;
	}

	status = eap_write_u32_t_network_order(
		data+sizeof(u32_t),
		sizeof(u32_t),
		outvalue[least_significant_u32_t_index]);
	if (status != eap_status_ok)
	{
		return status;
	}

	return eap_status_ok;
}

//-------------------------------------------------------------------

EAP_C_FUNC_EXPORT u64_t eap_shift_left_64_bit(u64_t value, u32_t shift)
{
	if (shift > 63u)
	{
		return 0ul;
	}
	else if (shift == 0)
	{
		return value;
	}

	u32_t *val = reinterpret_cast<u32_t *>(&value);
	u64_t out_buf;
	u32_t *out = reinterpret_cast<u32_t *>(&out_buf);

	if (shift < 32ul)
	{
		out[0] = val[0] << shift;
		out[1] = (val[1] << shift) | val[0] >> (32ul - shift);
	}
	else
	{
		out[0] = 0ul;
		out[1] = val[0] << (shift - 32ul);
	}

	return out_buf;
}

EAP_C_FUNC_EXPORT u64_t eap_shift_right_64_bit(u64_t value, u32_t shift)
{
	if (shift > 63u)
	{
		return 0ul;
	}
	else if (shift == 0)
	{
		return value;
	}

	u32_t *val = reinterpret_cast<u32_t *>(&value);
	u64_t out_buf;
	u32_t *out = reinterpret_cast<u32_t *>(&out_buf);

	if (shift < 32ul)
	{
		out[0] = (val[0] >> shift) | val[1] << (32ul - shift);
		out[1] = val[1] >> shift;
	}
	else
	{
		out[0] = val[1] >> (shift - 32ul);
		out[1] = 0ul;
	}

	return out_buf;
}

//------------------------------------------------------------------------------



// End.
