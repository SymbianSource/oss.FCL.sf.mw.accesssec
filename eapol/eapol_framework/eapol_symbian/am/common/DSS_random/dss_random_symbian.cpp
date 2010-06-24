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
* %version: 10.1.4 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 142 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include <bigint.h>

#include "dss_random.h"

#include "eap_am_assert.h"
#include "abs_eap_am_crypto.h"

#include "eap_am_crypto_sha1.h"

/** @file */

/** This is the block size in bytes. */
const u32_t BLOCK_SIZE = 160/8;

#if defined(EAP_DEBUG_TRACE_ACTIVE)
	const u32_t DEBUG_BUFFER_SIZE = 64;
#endif //#if defined(EAP_DEBUG_TRACE_ACTIVE)


LOCAL_C void dss_pseudo_randomL(abs_eap_am_tools_c * const m_am_tools, u8_t *out, u32_t out_length, u8_t *xkey, u32_t xkey_length);


/**
 *  dss_random_G() implements the G() function using modified SHA-1.
 *  @code
 *  Copied from "Multiple Examples of DSA" http://csrc.nist.gov/encryption/dss/Examples-1024bit.pdf.
 *  Using the revised algorithm found in the Change Notice for the generation of x values:
 *      XKEY= bd029bbe 7f51960b cf9edb2b 61f06f0f eb5a38b6
 *      XSEED= 00000000 00000000 00000000 00000000 00000000
 *  The first loop through step 3.2 provides:
 *      XVAL= bd029bbe 7f51960b cf9edb2b 61f06f0f eb5a38b6
 *  Using the routine in Appendix 3.3 Constructing The Function G From SHA-1
 *  provides:
 *      w[0]= 2070b322 3dba372f de1c0ffc 7b2e3b49 8b260614
 *  The following value is the updated XKEY value from step 3.2.c:
 *      XKEY= dd734ee0 bd0bcd3b adbaeb27 dd1eaa59 76803ecb
 *  The second loop through step 3.2 provides:
 *      XVAL= dd734ee0 bd0bcd3b adbaeb27 dd1eaa59 76803ecb
 *  Using the routine in Appendix 3.3 Constructing The Function G From SHA-1
 *  provides:
 *      w[1]= 3c6c18ba cb0f6c55 babb1378 8e20d737 a3275116
 *  The following value is the updated XKEY value from step 3.2.c:
 *      XKEY= 19df679b 881b3991 6875fea0 6b3f8191 19a78fe2
 *  Step 3.3 provides the following values:
 *      w[0] || w[1]= 2070b322 3dba372f de1c0ffc 7b2e3b49 8b260614
 *                    3c6c18ba cb0f6c55 babb1378 8e20d737 a3275116
 *      X= 47c27eb6 16dba413 91e5165b e9c5e397 7e39a15d
 *  @endcode
*/
eap_status_e dss_random_G(abs_eap_am_tools_c * const m_am_tools, u8_t *out, u32_t out_length, const u8_t *c, u32_t c_length)
{
	u32_t *out_array = reinterpret_cast<u32_t *>(out);

	eap_am_crypto_sha1_c sha1(m_am_tools);
	u32_t output_length = out_length;

	eap_status_e status = sha1.eap_sha1_dss_G_function(
		c,
		c_length,
		out_array,
		&output_length
		);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("ERROR: eap_sha1_dss_G_function(): status = %d"),
			status));
		return status;
	}

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("dss_random_G(): out_array"),
		out_array, sizeof(out_array)*5));

	return status;
}

/**
 *  dss_pseudo_random() implements pseudo random function for key generation of EAP/SIM.
 *  @code
 *  Random generator becomes as follows:
 *  Step 1. Choose a new, secret value for the seed-key, XKEY.
 *  Step 2. In hexadecimal notation let
 *              t = 67452301 EFCDAB89 98BADCFE 10325476 C3D2E1F0.
 *              This is the initial value for H0 || H1 || H2 || H3 || H4 in the SHS.
 *  Step 3. For j = 0 to m - 1 do
 *              c. xj = G(t,XKEY).
 *              d. XKEY = (1 + XKEY + xj) mod 2^b.
 *  @endcode
*/
EAP_FUNC_EXPORT eap_status_e dss_pseudo_random(abs_eap_am_tools_c * const m_am_tools, u8_t *out, u32_t out_length, u8_t *xkey, u32_t xkey_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_DEFAULT);
	eap_status_e status = eap_status_ok;
	__UHEAP_MARK;

	TRAPD(err, dss_pseudo_randomL(m_am_tools, out, out_length, xkey, xkey_length));
	if (err != KErrNone)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	__UHEAP_MARKEND;
	return status; 
}

LOCAL_C void dss_pseudo_randomL(abs_eap_am_tools_c * const m_am_tools, u8_t *out, u32_t out_length, u8_t *xkey, u32_t xkey_length)
{
	EAP_UNREFERENCED_PARAMETER(xkey_length);

	u32_t block_count = out_length/BLOCK_SIZE;
	if ((out_length % BLOCK_SIZE) != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: dss_pseudo_random(): out buffer length 0x%08x not aligned to 0x%08x.\n"),
			out_length, BLOCK_SIZE));

		User::Leave(KErrArgument);
	}

	TBuf8<BLOCK_SIZE> tmp_out;
	TBuf8<BLOCK_SIZE> tmp_xkey;

	tmp_xkey.Append(xkey, BLOCK_SIZE);

#if defined(EAP_DEBUG_TRACE_ACTIVE)
	u8_t debug_buffer[DEBUG_BUFFER_SIZE];
#endif //#if defined(EAP_DEBUG_TRACE_ACTIVE)

	EAP_TRACE_DATA_DEBUG(
		m_am_tools,
		TRACE_FLAGS_EAP_AM_CRYPTO,
		(EAPL("dss_pseudo_random(): xkey"),
		xkey, xkey_length));
	
	RInteger bn_xkey = RInteger::NewL(tmp_xkey);
	CleanupStack::PushL(bn_xkey);

	RInteger bn_two = RInteger::NewL(2);
	CleanupStack::PushL(bn_two);

	RInteger bn_160 = RInteger::NewL(160);
	CleanupStack::PushL(bn_160);

	// Calculate 2^160
	RInteger bn_mod = bn_two.ExponentiateL(bn_160);

	CleanupStack::PopAndDestroy(&bn_160);
	CleanupStack::PopAndDestroy(&bn_two);

	CleanupStack::PushL(bn_mod);

	for (u32_t ind = 0; ind < block_count; ind++)
	{
		eap_status_e status = dss_random_G(m_am_tools, &(out[ind*BLOCK_SIZE]), BLOCK_SIZE, tmp_xkey.Ptr(), BLOCK_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("ERROR: dss_random_G(): status = %d"),
																	status));
			User::Leave(KErrGeneral);
		}

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("dss_pseudo_random(): xj = G(xkey)"),
			&(out[ind*BLOCK_SIZE]), BLOCK_SIZE));

		if (ind+1u >= block_count)
		{
			break;
		}

		// Get the calculated block to be used
		tmp_out.Copy(&(out[ind*BLOCK_SIZE]), BLOCK_SIZE);

		// This must be constructed inside the loop because the only way
		// to assign descriptor values to CInteger seems to be by using NewLC.
		RInteger bn_xj = RInteger::NewL(tmp_out);	
		CleanupStack::PushL(bn_xj);

		// Calculate bn_xkey = (XKEY + 1 + xj) mod 2^b
		bn_xkey += 1;
		bn_xkey += bn_xj;
		bn_xkey %= bn_mod;

		// New tmp_xkey
		tmp_xkey.Copy(bn_xkey.BufferLC()->Des());

		CleanupStack::PopAndDestroy(); // bn_xkey buffer
		CleanupStack::PopAndDestroy(&bn_xj);

		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			(EAPL("dss_pseudo_random(): xkey[%d] = (1 + xkey[%d] + x[%d]) % mod\n"),
			ind+1u,
			ind,
			ind));

		EAP_TRACE_FORMAT(
			m_am_tools,
			(debug_buffer,
			sizeof(debug_buffer),
			EAPL("xkey[%d]"),
			ind+1u));

		EAP_TRACE_DATA_DEBUG(
			m_am_tools,
			TRACE_FLAGS_EAP_AM_CRYPTO,
			((eap_format_string)debug_buffer,
			tmp_xkey.Ptr(),
			tmp_xkey.Length()));

	} // for()

	CleanupStack::PopAndDestroy(&bn_mod);
	CleanupStack::PopAndDestroy(&bn_xkey);
}


// End.
