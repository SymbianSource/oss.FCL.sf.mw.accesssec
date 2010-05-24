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
	#define EAP_FILE_NUMBER_ENUM 7 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)



#include "eap_am_memory.h"
#include "eap_am_crypto_sha1.h"

//--------------------------------------------------

#if 1
	#define EAP_SHA1_TRACE_DEBUG EAP_TRACE_DEBUG
	#define EAP_SHA1_TRACE_DATA_DEBUG EAP_TRACE_DATA_DEBUG
#else
	#define EAP_SHA1_TRACE_DEBUG(tools, flags, params)
	#define EAP_SHA1_TRACE_DATA_DEBUG(object_name, flags, _parameter_list_)
#endif

#if defined(USE_EAP_TRACE)	
	static const u32_t EAP_TRACE_MASK_SHA1 = eap_am_tools_c::eap_trace_mask_crypto_sha1;
#endif //#if defined(USE_EAP_TRACE)	

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_crypto_sha1_c::~eap_am_crypto_sha1_c()
{
	hash_cleanup();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_am_crypto_sha1_c::eap_am_crypto_sha1_c(
	abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_saved_data(tools)
	, m_full_hashed_data_length(0ul)
	, m_is_valid(false)
{
	m_H[0] = 0;
	m_T[0] = 0;
	m_W_in_host_order[0] = 0;

	if (m_saved_data.get_is_valid() == false)
	{
		return;
	}

	eap_status_e status = hash_init();
	if (status != eap_status_ok)
	{
		return;
	}

	set_is_valid();
}

//------------------------------------------------------------

/**
 * The set_is_invalid() function sets the state of the eap_am_crypto_sha1_c
 * object invalid. 
 * The eap_am_crypto_sha1_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_sha1_c::set_is_invalid()
{
	m_is_valid = false;
}

//------------------------------------------------------------

/**
 * The set_is_valid() function sets the state of the eap_am_crypto_sha1_c
 * object valid. 
 * The eap_am_crypto_sha1_c object calls this function after it is initialized.
 */
EAP_FUNC_EXPORT void eap_am_crypto_sha1_c::set_is_valid()
{
	m_is_valid = true;
}

//------------------------------------------------------------

/**
 * The get_is_valid() function returns the status of the eap_am_crypto_sha1_c
 * object. 
 * True indicates the object is allocated successfully.
 */
EAP_FUNC_EXPORT bool eap_am_crypto_sha1_c::get_is_valid()
{
	return m_is_valid;
}

//--------------------------------------------------

inline u32_t eap_am_crypto_sha1_c::eap_sha1_rotate(
	const u32_t value,
	const u32_t shift
	)
{
	return (value << shift) | (value >> (32ul - shift));
}

//--------------------------------------------------

inline u32_t eap_am_crypto_sha1_c::eap_sha1_b_substitution(
	const u32_t Wt_3,
	const u32_t Wt_8,
	const u32_t Wt_14,
	const u32_t Wt_16
	)
{
	return eap_sha1_rotate(Wt_3 ^ Wt_8 ^ Wt_14 ^ Wt_16, 1ul);
}

//--------------------------------------------------

inline u32_t eap_am_crypto_sha1_c::eap_sha1_ft_0_19(
	const u32_t B,
	const u32_t C,
	const u32_t D
	)
{
	return (((C ^ D) & B) ^ D);
}

//--------------------------------------------------

inline u32_t eap_am_crypto_sha1_c::eap_sha1_ft_20_39(
	const u32_t B,
	const u32_t C,
	const u32_t D
	)
{
	return (B ^ C ^ D);
}

//--------------------------------------------------

inline u32_t eap_am_crypto_sha1_c::eap_sha1_ft_40_59(
	const u32_t B,
	const u32_t C,
	const u32_t D
	)
{
	return ((B & C) | ((B | C) & D));
}

//--------------------------------------------------

inline u32_t eap_am_crypto_sha1_c::eap_sha1_ft_60_79(
	const u32_t B,
	const u32_t C,
	const u32_t D
	)
{
	return eap_sha1_ft_20_39(B, C, D);
}

//--------------------------------------------------

inline void eap_am_crypto_sha1_c::d_substitution(
	u32_t * const A,
	u32_t * const B,
	u32_t * const C,
	u32_t * const D,
	u32_t * const E,
	const u32_t temp
	)
{
	*E = *D;
	*D = *C;
	*C = eap_sha1_rotate(*B, 30ul);
	*B = *A;
	*A = temp;
}

//--------------------------------------------------

inline void eap_am_crypto_sha1_c::d_substitution_0_15(
	const u32_t t,
	u32_t * const A,
	u32_t * const B,
	u32_t * const C,
	u32_t * const D,
	u32_t * const E,
	const u32_t Wt
	)
{
	EAP_UNREFERENCED_PARAMETER(t);

	const u32_t TEMP = eap_sha1_rotate(*A, 5ul)
		+ eap_sha1_ft_0_19(*B, *C, *D)
		+ *E + Wt + eap_am_crypto_sha1_c::EAP_SHA1_K__0_19;

	d_substitution(A, B, C, D, E, TEMP);

	EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\n"),
					 t, *A, *B, *C, *D, *E));
}

//--------------------------------------------------

inline void eap_am_crypto_sha1_c::d_substitution_16_19(
	const u32_t t,
	u32_t * const A,
	u32_t * const B,
	u32_t * const C,
	u32_t * const D,
	u32_t * const E,
	u32_t * const Wt,
	const u32_t Wt_3,
	const u32_t Wt_8,
	const u32_t Wt_14,
	const u32_t Wt_16
	)
{
	EAP_UNREFERENCED_PARAMETER(t);

	*Wt = eap_sha1_b_substitution(Wt_3, Wt_8, Wt_14, Wt_16);

	const u32_t TEMP = eap_sha1_rotate(*A, 5ul)
		+ eap_sha1_ft_0_19(*B, *C, *D)
		+ *E + *Wt + eap_am_crypto_sha1_c::EAP_SHA1_K__0_19;

	d_substitution(A, B, C, D, E, TEMP);

	EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\n"),
					 t, *A, *B, *C, *D, *E));
}

//--------------------------------------------------

inline void eap_am_crypto_sha1_c::d_substitution_20_39(
	const u32_t t,
	u32_t * const A,
	u32_t * const B,
	u32_t * const C,
	u32_t * const D,
	u32_t * const E,
	u32_t * const Wt,
	const u32_t Wt_3,
	const u32_t Wt_8,
	const u32_t Wt_14,
	const u32_t Wt_16
	)
{
	EAP_UNREFERENCED_PARAMETER(t);

	*Wt = eap_sha1_b_substitution(Wt_3, Wt_8, Wt_14, Wt_16);

	const u32_t TEMP = eap_sha1_rotate(*A, 5ul)
		+ eap_sha1_ft_20_39(*B, *C, *D)
		+ *E + *Wt + eap_am_crypto_sha1_c::EAP_SHA1_K_20_39;

	d_substitution(A, B, C, D, E, TEMP);

	EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\n"),
					 t, *A, *B, *C, *D, *E));
}

//--------------------------------------------------

inline void eap_am_crypto_sha1_c::d_substitution_40_59(
	const u32_t t,
	u32_t * const A,
	u32_t * const B,
	u32_t * const C,
	u32_t * const D,
	u32_t * const E,
	u32_t * const Wt,
	const u32_t Wt_3,
	const u32_t Wt_8,
	const u32_t Wt_14,
	const u32_t Wt_16
	)
{
	EAP_UNREFERENCED_PARAMETER(t);

	*Wt = eap_sha1_b_substitution(Wt_3, Wt_8, Wt_14, Wt_16);

	const u32_t TEMP = eap_sha1_rotate(*A, 5ul)
		+ eap_sha1_ft_40_59(*B, *C, *D)
		+ *E + *Wt + static_cast<u32_t>(eap_am_crypto_sha1_c::EAP_SHA1_K_40_59);

	d_substitution(A, B, C, D, E, TEMP);

	EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\n"),
					 t, *A, *B, *C, *D, *E));
}

//--------------------------------------------------

inline void eap_am_crypto_sha1_c::d_substitution_60_79(
	const u32_t t,
	u32_t * const A,
	u32_t * const B,
	u32_t * const C,
	u32_t * const D,
	u32_t * const E,
	u32_t * const Wt,
	const u32_t Wt_3,
	const u32_t Wt_8,
	const u32_t Wt_14,
	const u32_t Wt_16
	)
{
	EAP_UNREFERENCED_PARAMETER(t);

	*Wt = eap_sha1_b_substitution(Wt_3, Wt_8, Wt_14, Wt_16);

	const u32_t TEMP = eap_sha1_rotate(*A, 5ul)
		+ eap_sha1_ft_60_79(*B, *C, *D)
		+ *E + *Wt + static_cast<u32_t>(eap_am_crypto_sha1_c::EAP_SHA1_K_60_79);

	d_substitution(A, B, C, D, E, TEMP);

	EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: t=%d\t%08x\t%08x\t%08x\t%08x\t%08x\n"),
					 t, *A, *B, *C, *D, *E));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e
eap_am_crypto_sha1_c::eap_sha1_process_data_host_order(
	const u32_t * W,
	u32_t W_count
	)
{
	u32_t A;
	u32_t B;
	u32_t C;
	u32_t D;
	u32_t E;

	if (W == 0
		//|| (reinterpret_cast<u32_t>(W) % sizeof(u32_t)) != 0
		|| W_count == 0
		|| (W_count % EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT) != 0)
	{
		EAP_ASSERT_ANYWAY;
		EAP_SYSTEM_DEBUG_BREAK();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}


	#if defined(_DEBUG)
		for (u32_t ind = 0ul; ind < W_count; ind++)
		{
			EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
						(EAPL("SHA1: W[%d]=%08x\n"),
						 ind,
						 W[ind]));
		} // for()
	#endif //#if defined(_DEBUG)


	do
	{

		#if defined(_DEBUG)
			EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: H[0]=0x%08x, H[1]=0x%08x, H[2]=0x%08x, H[3]=0x%08x, H[4]=0x%08x\n"),
					 m_H[0],
					 m_H[1],
					 m_H[2],
					 m_H[3],
					 m_H[4]));
			EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: % 4s\t% 8s\t% 8s\t% 8s\t% 8s\t% 8s\n"),
					"t", "A", "B", "C", "D", "E"));
		#endif //#if defined(_DEBUG)

		A = m_H[0];
		B = m_H[1];
		C = m_H[2];
		D = m_H[3];
		E = m_H[4];

		d_substitution_0_15( 0, &A, &B, &C, &D, &E, W[ 0]);
		d_substitution_0_15( 1, &A, &B, &C, &D, &E, W[ 1]);
		d_substitution_0_15( 2, &A, &B, &C, &D, &E, W[ 2]);
		d_substitution_0_15( 3, &A, &B, &C, &D, &E, W[ 3]);
		d_substitution_0_15( 4, &A, &B, &C, &D, &E, W[ 4]);
		d_substitution_0_15( 5, &A, &B, &C, &D, &E, W[ 5]);
		d_substitution_0_15( 6, &A, &B, &C, &D, &E, W[ 6]);
		d_substitution_0_15( 7, &A, &B, &C, &D, &E, W[ 7]);
		d_substitution_0_15( 8, &A, &B, &C, &D, &E, W[ 8]);
		d_substitution_0_15( 9, &A, &B, &C, &D, &E, W[ 9]);
		d_substitution_0_15(10, &A, &B, &C, &D, &E, W[10]);
		d_substitution_0_15(11, &A, &B, &C, &D, &E, W[11]);
		d_substitution_0_15(12, &A, &B, &C, &D, &E, W[12]);
		d_substitution_0_15(13, &A, &B, &C, &D, &E, W[13]);
		d_substitution_0_15(14, &A, &B, &C, &D, &E, W[14]);
		d_substitution_0_15(15, &A, &B, &C, &D, &E, W[15]);

		d_substitution_16_19(16, &A, &B, &C, &D, &E, &(m_T[ 0]),
							 W[13], W[ 8], W[ 2], W[ 0]);
		d_substitution_16_19(17, &A, &B, &C, &D, &E, &(m_T[ 1]),
							 W[14], W[ 9], W[ 3], W[ 1]);
		d_substitution_16_19(18, &A, &B, &C, &D, &E, &(m_T[ 2]),
							 W[15], W[10], W[ 4], W[ 2]);
		d_substitution_16_19(19, &A, &B, &C, &D, &E, &(m_T[ 3]),
							 m_T[ 0], W[11], W[ 5], W[ 3]);

		d_substitution_20_39(20, &A, &B, &C, &D, &E, &(m_T[ 4]),
							 m_T[ 1], W[12], W[ 6], W[ 4]);
		d_substitution_20_39(21, &A, &B, &C, &D, &E, &(m_T[ 5]),
							 m_T[ 2], W[13], W[ 7], W[ 5]);
		d_substitution_20_39(22, &A, &B, &C, &D, &E, &(m_T[ 6]),
							 m_T[ 3], W[14], W[ 8], W[ 6]);
		d_substitution_20_39(23, &A, &B, &C, &D, &E, &(m_T[ 7]),
							 m_T[ 4], W[15], W[ 9], W[ 7]);
		d_substitution_20_39(24, &A, &B, &C, &D, &E, &(m_T[ 8]),
							 m_T[ 5], m_T[ 0], W[10], W[ 8]);
		d_substitution_20_39(25, &A, &B, &C, &D, &E, &(m_T[ 9]),
							 m_T[ 6], m_T[ 1], W[11], W[ 9]);
		d_substitution_20_39(26, &A, &B, &C, &D, &E, &(m_T[10]),
							 m_T[ 7], m_T[ 2], W[12], W[10]);
		d_substitution_20_39(27, &A, &B, &C, &D, &E, &(m_T[11]),
							 m_T[ 8], m_T[ 3], W[13], W[11]);
		d_substitution_20_39(28, &A, &B, &C, &D, &E, &(m_T[12]),
							 m_T[ 9], m_T[ 4], W[14], W[12]);
		d_substitution_20_39(29, &A, &B, &C, &D, &E, &(m_T[13]),
							 m_T[10], m_T[ 5], W[15], W[13]);
		d_substitution_20_39(30, &A, &B, &C, &D, &E, &(m_T[14]),
							 m_T[11], m_T[ 6], m_T[ 0], W[14]);
		d_substitution_20_39(31, &A, &B, &C, &D, &E, &(m_T[15]),
							 m_T[12], m_T[ 7], m_T[ 1], W[15]);
		d_substitution_20_39(32, &A, &B, &C, &D, &E, &(m_T[ 0]),
							 m_T[13], m_T[ 8], m_T[ 2], m_T[ 0]);
		d_substitution_20_39(33, &A, &B, &C, &D, &E, &(m_T[ 1]),
							 m_T[14], m_T[ 9], m_T[ 3], m_T[ 1]);
		d_substitution_20_39(34, &A, &B, &C, &D, &E, &(m_T[ 2]),
							 m_T[15], m_T[10], m_T[ 4], m_T[ 2]);
		d_substitution_20_39(35, &A, &B, &C, &D, &E, &(m_T[ 3]),
							 m_T[ 0], m_T[11], m_T[ 5], m_T[ 3]);
		d_substitution_20_39(36, &A, &B, &C, &D, &E, &(m_T[ 4]),
							 m_T[ 1], m_T[12], m_T[ 6], m_T[ 4]);
		d_substitution_20_39(37, &A, &B, &C, &D, &E, &(m_T[ 5]),
							 m_T[ 2], m_T[13], m_T[ 7], m_T[ 5]);
		d_substitution_20_39(38, &A, &B, &C, &D, &E, &(m_T[ 6]),
							 m_T[ 3], m_T[14], m_T[ 8], m_T[ 6]);
		d_substitution_20_39(39, &A, &B, &C, &D, &E, &(m_T[ 7]),
							 m_T[ 4], m_T[15], m_T[ 9], m_T[ 7]);

		d_substitution_40_59(40, &A, &B, &C, &D, &E, &(m_T[ 8]),
							 m_T[ 5], m_T[ 0], m_T[10], m_T[ 8]);
		d_substitution_40_59(41, &A, &B, &C, &D, &E, &(m_T[ 9]),
							 m_T[ 6], m_T[ 1], m_T[11], m_T[ 9]);
		d_substitution_40_59(42, &A, &B, &C, &D, &E, &(m_T[10]),
							 m_T[ 7], m_T[ 2], m_T[12], m_T[10]);
		d_substitution_40_59(43, &A, &B, &C, &D, &E, &(m_T[11]),
							 m_T[ 8], m_T[ 3], m_T[13], m_T[11]);
		d_substitution_40_59(44, &A, &B, &C, &D, &E, &(m_T[12]),
							 m_T[ 9], m_T[ 4], m_T[14], m_T[12]);
		d_substitution_40_59(45, &A, &B, &C, &D, &E, &(m_T[13]),
							 m_T[10], m_T[ 5], m_T[15], m_T[13]);
		d_substitution_40_59(46, &A, &B, &C, &D, &E, &(m_T[14]),
							 m_T[11], m_T[ 6], m_T[ 0], m_T[14]);
		d_substitution_40_59(47, &A, &B, &C, &D, &E, &(m_T[15]),
							 m_T[12], m_T[ 7], m_T[ 1], m_T[15]);
		d_substitution_40_59(48, &A, &B, &C, &D, &E, &(m_T[ 0]),
							 m_T[13], m_T[ 8], m_T[ 2], m_T[ 0]);
		d_substitution_40_59(49, &A, &B, &C, &D, &E, &(m_T[ 1]),
							 m_T[14], m_T[ 9], m_T[ 3], m_T[ 1]);
		d_substitution_40_59(50, &A, &B, &C, &D, &E, &(m_T[ 2]),
							 m_T[15], m_T[10], m_T[ 4], m_T[ 2]);
		d_substitution_40_59(51, &A, &B, &C, &D, &E, &(m_T[ 3]),
							 m_T[ 0], m_T[11], m_T[ 5], m_T[ 3]);
		d_substitution_40_59(52, &A, &B, &C, &D, &E, &(m_T[ 4]),
							 m_T[ 1], m_T[12], m_T[ 6], m_T[ 4]);
		d_substitution_40_59(53, &A, &B, &C, &D, &E, &(m_T[ 5]),
							 m_T[ 2], m_T[13], m_T[ 7], m_T[ 5]);
		d_substitution_40_59(54, &A, &B, &C, &D, &E, &(m_T[ 6]),
							 m_T[ 3], m_T[14], m_T[ 8], m_T[ 6]);
		d_substitution_40_59(55, &A, &B, &C, &D, &E, &(m_T[ 7]),
							 m_T[ 4], m_T[15], m_T[ 9], m_T[ 7]);
		d_substitution_40_59(56, &A, &B, &C, &D, &E, &(m_T[ 8]),
							 m_T[ 5], m_T[ 0], m_T[10], m_T[ 8]);
		d_substitution_40_59(57, &A, &B, &C, &D, &E, &(m_T[ 9]),
							 m_T[ 6], m_T[ 1], m_T[11], m_T[ 9]);
		d_substitution_40_59(58, &A, &B, &C, &D, &E, &(m_T[10]),
							 m_T[ 7], m_T[ 2], m_T[12], m_T[10]);
		d_substitution_40_59(59, &A, &B, &C, &D, &E, &(m_T[11]),
							 m_T[ 8], m_T[ 3], m_T[13], m_T[11]);

		d_substitution_60_79(60, &A, &B, &C, &D, &E, &(m_T[12]),
							 m_T[ 9], m_T[ 4], m_T[14], m_T[12]);
		d_substitution_60_79(61, &A, &B, &C, &D, &E, &(m_T[13]),
							 m_T[10], m_T[ 5], m_T[15], m_T[13]);
		d_substitution_60_79(62, &A, &B, &C, &D, &E, &(m_T[14]),
							 m_T[11], m_T[ 6], m_T[ 0], m_T[14]);
		d_substitution_60_79(63, &A, &B, &C, &D, &E, &(m_T[15]),
							 m_T[12], m_T[ 7], m_T[ 1], m_T[15]);
		d_substitution_60_79(64, &A, &B, &C, &D, &E, &(m_T[ 0]),
							 m_T[13], m_T[ 8], m_T[ 2], m_T[ 0]);
		d_substitution_60_79(65, &A, &B, &C, &D, &E, &(m_T[ 1]),
							 m_T[14], m_T[ 9], m_T[ 3], m_T[ 1]);
		d_substitution_60_79(66, &A, &B, &C, &D, &E, &(m_T[ 2]),
							 m_T[15], m_T[10], m_T[ 4], m_T[ 2]);
		d_substitution_60_79(67, &A, &B, &C, &D, &E, &(m_T[ 3]),
							 m_T[ 0], m_T[11], m_T[ 5], m_T[ 3]);
		d_substitution_60_79(68, &A, &B, &C, &D, &E, &(m_T[ 4]),
							 m_T[ 1], m_T[12], m_T[ 6], m_T[ 4]);
		d_substitution_60_79(69, &A, &B, &C, &D, &E, &(m_T[ 5]),
							 m_T[ 2], m_T[13], m_T[ 7], m_T[ 5]);
		d_substitution_60_79(70, &A, &B, &C, &D, &E, &(m_T[ 6]),
							 m_T[ 3], m_T[14], m_T[ 8], m_T[ 6]);
		d_substitution_60_79(71, &A, &B, &C, &D, &E, &(m_T[ 7]),
							 m_T[ 4], m_T[15], m_T[ 9], m_T[ 7]);
		d_substitution_60_79(72, &A, &B, &C, &D, &E, &(m_T[ 8]),
							 m_T[ 5], m_T[ 0], m_T[10], m_T[ 8]);
		d_substitution_60_79(73, &A, &B, &C, &D, &E, &(m_T[ 9]),
							 m_T[ 6], m_T[ 1], m_T[11], m_T[ 9]);
		d_substitution_60_79(74, &A, &B, &C, &D, &E, &(m_T[10]),
							 m_T[ 7], m_T[ 2], m_T[12], m_T[10]);
		d_substitution_60_79(75, &A, &B, &C, &D, &E, &(m_T[11]),
							 m_T[ 8], m_T[ 3], m_T[13], m_T[11]);
		d_substitution_60_79(76, &A, &B, &C, &D, &E, &(m_T[12]),
							 m_T[ 9], m_T[ 4], m_T[14], m_T[12]);
		d_substitution_60_79(77, &A, &B, &C, &D, &E, &(m_T[13]),
							 m_T[10], m_T[ 5], m_T[15], m_T[13]);
		d_substitution_60_79(78, &A, &B, &C, &D, &E, &(m_T[14]),
							 m_T[11], m_T[ 6], m_T[ 0], m_T[14]);
		d_substitution_60_79(79, &A, &B, &C, &D, &E, &(m_T[15]),
							 m_T[12], m_T[ 7], m_T[ 1], m_T[15]);

		m_H[0] = m_H[0] + A;
		m_H[1] = m_H[1] + B;
		m_H[2] = m_H[2] + C;
		m_H[3] = m_H[3] + D;
		m_H[4] = m_H[4] + E;

		W_count -= EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT;
		W += EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT;

	} while(W_count > 0ul);

	EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: digest=\t%08x\t%08x\t%08x\t%08x\t%08x\n"),
					 m_H[0], m_H[1], m_H[2], m_H[3], m_H[4]));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e
eap_am_crypto_sha1_c::eap_sha1_process_data_network_order(
	const u32_t * W,
	u32_t W_count
	)
{
	if (W == 0
		//|| (reinterpret_cast<u32_t>(W) % sizeof(u32_t)) != 0
		|| W_count == 0
		|| (W_count % EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT) != 0)
	{
		EAP_ASSERT_ANYWAY;
		EAP_SYSTEM_DEBUG_BREAK();
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = eap_status_ok;

	// Array of 16 temporary 32-bit unsigned integers.
	u32_t count = W_count / EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT;	

	for (u32_t ind = 0ul; ind < count; ind++)
	{	
		for (u32_t ind_W = 0ul; ind_W < EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT
				 ; ind_W++)
		{
			// Here we must read data in 8-bit blocks bacause W can be aligned at any position.
			const u8_t * const data
				= reinterpret_cast<const u8_t *>(
					&W[ind*EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT+ind_W]);
			m_W_in_host_order[ind_W]
				= (data[0] << 24)
				| (data[1] << 16)
				| (data[2] <<  8)
				| (data[3] <<  0);
		} // for()
	
		status = eap_sha1_process_data_host_order(
			m_W_in_host_order,
			EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	
	} // for()
	
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha1_c::copy_message_digest(
	void * const output,
	u32_t * const max_output_size)
{
	if (output == 0
		|| max_output_size == 0
		|| *max_output_size < EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

#if defined(EAP_LITTLE_ENDIAN)
	// We must change the data from host order to network order.
	u32_t * const tmp_H = static_cast<u32_t *>(output);
	for (u32_t ind = 0ul; ind < EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_u32_COUNT
			 ; ind++)
	{
		tmp_H[ind] = eap_htonl(m_H[ind]);
	} // for()

#elif defined(EAP_BIG_ENDIAN)

	m_am_tools->memmove(
		output,
		m_H,
		EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE);

#else
#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
#endif

	*max_output_size = EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE;

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha1_c::eap_sha1_dss_G_function(
	const void * const data,
	const u32_t data_length,
	void * const output,
	u32_t * const output_length
	)
{
	if (data == 0
		|| data_length == 0
		|| data_length > EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE
		|| output == 0
		|| output_length == 0
		|| *output_length < EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = hash_init();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	m_am_tools->memset(m_W_in_host_order, 0, sizeof(m_W_in_host_order));
	m_am_tools->memmove(m_W_in_host_order, data, data_length);


#if defined(EAP_LITTLE_ENDIAN)

	{
		for (u32_t ind_W = 0ul; ind_W < EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT
				 ; ind_W++)
		{
			m_W_in_host_order[ind_W] = eap_ntohl(m_W_in_host_order[ind_W]);
		} // for()

		status = eap_sha1_process_data_host_order(
			m_W_in_host_order,
			EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#elif defined(EAP_BIG_ENDIAN)

	{
		u32_t count_W = data_length
			/ EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE;

		status = eap_sha1_process_data_host_order(m_W_in_host_order, count_W);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

#else
#error ERROR: define EAP_LITTLE_ENDIAN (byte 0 is least significant (i386)) \
or EAP_BIG_ENDIAN (byte 0 is most significant (mc68k)).
#endif

	status = copy_message_digest(
		output,
		output_length);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This function returns the size of message digest of HASH-algorithm.
 */
EAP_FUNC_EXPORT u32_t eap_am_crypto_sha1_c::get_digest_length()
{
	return EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE;
}

//--------------------------------------------------

/**
 * This function returns the size of block of HASH-algorithm.
 */
EAP_FUNC_EXPORT u32_t eap_am_crypto_sha1_c::get_block_size()
{
	return EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE;
}

//--------------------------------------------------

/**
 * This function initializes the context of SHA1-algorithm.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha1_c::hash_init()
{
	m_full_hashed_data_length = 0ul;

	m_H[0] = static_cast<u32_t>(EAP_SHA1_INIT_H0);
	m_H[1] = static_cast<u32_t>(EAP_SHA1_INIT_H1);
	m_H[2] = static_cast<u32_t>(EAP_SHA1_INIT_H2);
	m_H[3] = static_cast<u32_t>(EAP_SHA1_INIT_H3);
	m_H[4] = static_cast<u32_t>(EAP_SHA1_INIT_H4);

	if (m_saved_data.get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = m_saved_data.set_data_length(0ul);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------
/**
 * This function updates the context of SHA1-algorithm with data.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha1_c::hash_update(
	const void * const data,
	const u32_t data_length)
{
	eap_status_e status = eap_status_ok;
	u32_t prosessed_data_length = 0ul;
	
		
	m_full_hashed_data_length += data_length;

	EAP_SHA1_TRACE_DEBUG(m_am_tools, EAP_TRACE_MASK_SHA1,
					(EAPL("SHA1: Processed data length %u\n"),
					 m_full_hashed_data_length));

	if (m_saved_data.get_is_valid_data() == true
		&& m_saved_data.get_data_length() > 0ul)
	{
		EAP_SHA1_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_SHA1,
			(EAPL("SHA1 saved data"),
			 m_saved_data.get_data(m_saved_data.get_data_length()),
			 m_saved_data.get_data_length()));
		
		// Here we have remaining data to process from previous call
		// of hash_update().
		u32_t needed_data_length = EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE
			- m_saved_data.get_data_length();
		if (needed_data_length > data_length)
		{
			// Not enough input data.
			needed_data_length = data_length;
		}

		prosessed_data_length = needed_data_length;
		status = m_saved_data.add_data(data, needed_data_length);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		if (m_saved_data.get_data_length()
			== EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE)
		{
			// Enough data to process.
			// Just one block of integers in W array.

			status = eap_sha1_process_data_network_order(
				reinterpret_cast<const u32_t *>(
					m_saved_data.get_data(
						m_saved_data.get_data_length())),
				EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT
				);
		
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// This is optimization of buffer allocations.
			status = m_saved_data.set_data_length(0ul);
			if (status != eap_status_ok)
			{
				return EAP_STATUS_RETURN(m_am_tools, status);
			}
		}
		
		EAP_ASSERT(m_saved_data.get_is_valid_data() == false
		|| m_saved_data.get_data_length()
			   <= EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE);
	
	}

	u32_t remaining_data_length = data_length - prosessed_data_length;
	u32_t full_block_count = remaining_data_length
		/ EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE;

	if (full_block_count > 0ul)
	{
		// Here we have full blocks to process.
		status = eap_sha1_process_data_network_order(
			reinterpret_cast<const u32_t *>(
				static_cast<const u8_t *>(data)+prosessed_data_length),
			full_block_count * EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT
			);
		
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}

		prosessed_data_length += sizeof(u32_t) * full_block_count
			* EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT;
	}
	if (data_length > prosessed_data_length)
	{
		// Save the remaining data.
		status = m_saved_data.add_data(
			static_cast<const u8_t *>(data)+prosessed_data_length,
			data_length-prosessed_data_length);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

/**
 * This function writes the message digest to buffer.
 * @param Length is set if md_length_or_null is non-NULL.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha1_c::hash_final(
	void * const message_digest,
	u32_t *md_length_or_null)
{
	eap_status_e status = eap_status_ok;

	if (message_digest == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (m_saved_data.get_is_valid_data() == true)
	{
		EAP_SHA1_TRACE_DATA_DEBUG(
			m_am_tools,
			EAP_TRACE_MASK_SHA1,
			(EAPL("SHA1 saved data"),
			 m_saved_data.get_data(m_saved_data.get_data_length()),
			 m_saved_data.get_data_length()));
	}

	// First add the one bit. We use one byte 0x80.
	u8_t bit_pad = 0x80;
	status = m_saved_data.add_data(&bit_pad, sizeof(bit_pad));
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// Here we may have remaining data to process from previous call
	// of hash_update().
	u32_t min_data_length = m_saved_data.get_data_length() + sizeof(u64_t);
	u32_t padding_zero_count = 0ul;
	u32_t block_count = min_data_length / EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE;
	if ((min_data_length % EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE) != 0)
	{
		// Last block is not full.
		++block_count;
	}
	padding_zero_count = (block_count*EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE)
		- min_data_length;

	// Now we need to pad the remaining data.
	u32_t data_length = m_saved_data.get_data_length();
	status = m_saved_data.set_buffer_length(data_length+padding_zero_count);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	m_saved_data.set_data_length(data_length+padding_zero_count);

	u8_t * const padding = m_saved_data.get_data_offset(data_length, padding_zero_count);
	if (padding == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_buffer_too_short);
	}

	m_am_tools->memset(
		padding,
		0,
		padding_zero_count);

	// And finally the length of the hashed data is added to block.
	// Note the length is in bits.
	u64_t full_hashed_data_length_in_network_order
		= eap_htonll(eap_shift_left_64_bit(m_full_hashed_data_length, 3ul));
	status = m_saved_data.add_data(
		&full_hashed_data_length_in_network_order,
		sizeof(full_hashed_data_length_in_network_order));
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_ASSERT(m_saved_data.get_data_length()
			   >= EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE
			   && (m_saved_data.get_data_length()
				   % EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE) == 0);

	u32_t full_block_count = m_saved_data.get_data_length()
		/ EAP_AM_CRYPTO_SHA1_BLOCK_BYTE_SIZE;

	status = eap_sha1_process_data_network_order(
		reinterpret_cast<const u32_t *>(
			m_saved_data.get_data(
				m_saved_data.get_data_length())),
		full_block_count * EAP_AM_CRYPTO_SHA1_BLOCK_u32_COUNT
		);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	// This is optimization of buffer allocations.
	status = m_saved_data.set_data_length(0ul);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}


	u32_t output_length = 0ul;
	if (md_length_or_null == 0)
	{
		// Let's use temporary length variable.
		output_length = EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE;
		md_length_or_null = &output_length;
	}

	status = copy_message_digest(
		message_digest,
		md_length_or_null);
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function cleans up the SHA1 context.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha1_c::hash_cleanup()
{
	m_saved_data.reset();

	m_full_hashed_data_length = 0ul;

	m_am_tools->memset(m_H, 0, EAP_AM_CRYPTO_SHA1_DIGEST_BUFFER_BYTE_SIZE);

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function copies the context of SHA1.
 */
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_sha1_c::copy_context(
	const eap_variable_data_c * const saved_data,
	const u64_t full_hashed_data_length,
	const u32_t * const H,
	const u32_t * const T,
	const u32_t * const W_in_host_order)
{
	if (saved_data->get_is_valid_data() == true)
	{
		eap_status_e status = m_saved_data.set_copy_of_buffer(saved_data);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}
	else
	{
		// No saved data. Just reset.
		m_saved_data.reset();
	}
	
	m_full_hashed_data_length = full_hashed_data_length;

	m_am_tools->memmove(m_H, H, sizeof(m_H));

	m_am_tools->memmove(m_T, T, sizeof(m_T));

	m_am_tools->memmove(m_W_in_host_order, W_in_host_order, sizeof(m_W_in_host_order));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

/**
 * This function copies the context of SHA1.
 */
EAP_FUNC_EXPORT eap_am_crypto_sha1_c * eap_am_crypto_sha1_c::copy()
{
	eap_am_crypto_sha1_c * const sha1 = new eap_am_crypto_sha1_c(m_am_tools);
	if (sha1 == 0
		|| sha1->get_is_valid() == false)
	{
		delete sha1;
		return 0;
	}

	eap_status_e status = sha1->copy_context(
		&m_saved_data,
		m_full_hashed_data_length,
		m_H,
		m_T,
		m_W_in_host_order);
	if (status != eap_status_ok)
	{
		delete sha1;
		return 0;
	}

	return sha1;
}

//--------------------------------------------------



// End.
