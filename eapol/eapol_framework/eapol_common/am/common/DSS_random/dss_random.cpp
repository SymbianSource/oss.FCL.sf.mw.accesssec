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
* %version: 10.1.5 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 8 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


#include "eap_am_memory.h"

#include "dss_random.h"

#include "eap_am_assert.h"
#include "abs_eap_am_crypto.h"

#include <openssl/bn.h>

#include "eap_am_crypto_sha1.h"

/** @file */

/** This is the block size in bytes. */
static const u32_t BLOCK_SIZE = 160/8;

static const u32_t DEBUG_BUFFER_SIZE = 80;


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
eap_status_e dss_random_G(abs_eap_am_tools_c * const m_am_tools, u8_t *out, u32_t out_length, u8_t *c, u32_t c_length)
{
	u32_t *out_array = reinterpret_cast<u32_t *>(out);

	EAP_ASSERT(out_length == BLOCK_SIZE);
	EAP_ASSERT(c_length == BLOCK_SIZE);

	{
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
		}

		return status;
	}
}

#define CLEAN_OPENSSL_BN(ctx) \
	{ \
	BN_free(&bn_mod); \
	BN_free(&bn_tmp); \
	BN_free(&bn_xkey); \
	BN_free(&bn_xj); \
	BN_free(&bn_one); \
	BN_free(&bn_160); \
	BN_CTX_free(ctx); \
	}

/**
 *  dss_pseudo_random() implements pseudo random function for key genearation of EAP/SIM.
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
eap_status_e dss_pseudo_random(abs_eap_am_tools_c * const m_am_tools, u8_t *out, u32_t out_length, u8_t *xkey, u32_t xkey_length)
{
	u32_t block_count = out_length/BLOCK_SIZE;
	if ((out_length % BLOCK_SIZE) != 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools, 
			TRACE_FLAGS_DEFAULT, 
			(EAPL("ERROR: dss_pseudo_random(): out buffer length 0x%08x not aligned to 0x%08x.\n"),
			 out_length, BLOCK_SIZE));
		return eap_status_data_length_not_aligned_to_block_size;
	}

	if (xkey == 0
		|| out == 0)
	{
		return eap_status_illegal_parameter;
	}

	u8_t tmp_xkey[BLOCK_SIZE];

	m_am_tools->memmove(tmp_xkey, xkey, BLOCK_SIZE);

	BN_CTX *ctx;
	BIGNUM bn_mod, bn_xkey, bn_xj, bn_one, bn_160, bn_tmp;

	ctx=BN_CTX_new();
	BN_init(&bn_mod);
	BN_init(&bn_tmp);
	BN_init(&bn_xkey);
	BN_init(&bn_xj);
	BN_init(&bn_one);
	BN_init(&bn_160);

	BN_set_word(&bn_one, 1);
	BN_set_word(&bn_mod, 2);
	BN_set_word(&bn_160, 160);

	// bn_mod = 2^160
	BN_exp(&bn_mod, &bn_mod, &bn_160, ctx);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("dss_pseudo_random(): mod"),
		bn_mod.d, bn_mod.top*sizeof(BN_ULONG)));

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("xkey[0]"),
		xkey, xkey_length));

	for (u32_t ind = 0; ind < block_count; ind++)
	{
		u8_t debug_buffer[DEBUG_BUFFER_SIZE];
		EAP_UNREFERENCED_PARAMETER(debug_buffer);

		eap_status_e status = dss_random_G(m_am_tools, &(out[ind*BLOCK_SIZE]), BLOCK_SIZE, tmp_xkey, BLOCK_SIZE);
		if (status != eap_status_ok)
		{
			EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("ERROR: dss_random_G(): status = %d"),
				status));

			CLEAN_OPENSSL_BN(ctx);

			return status;
		}

		EAP_TRACE_FORMAT(m_am_tools, (debug_buffer, DEBUG_BUFFER_SIZE, EAPL("w[%d]   "), ind));
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("dss_pseudo_random(): %s = G(xkey[%d])\n"),
			debug_buffer,
			ind));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (reinterpret_cast<eap_format_string>(debug_buffer),
			&(out[ind*BLOCK_SIZE]), BLOCK_SIZE));

		if (ind+1u >= block_count)
		{
			break;
		}

		BN_bin2bn(static_cast<u8_t *>(tmp_xkey), BLOCK_SIZE, &bn_xkey);

		// tmp = (xkey + 1) % mod
		BN_mod_add(&bn_tmp, &bn_xkey, &bn_one, &bn_mod, ctx);

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("dss_pseudo_random(): tmp[%d] = (xkey[%d] + 1) % mod\n"),
			ind,
			ind));
		EAP_TRACE_FORMAT(m_am_tools, (debug_buffer, DEBUG_BUFFER_SIZE, EAPL("tmp[%d] "), ind));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (reinterpret_cast<eap_format_string>(debug_buffer),
			bn_tmp.d, bn_tmp.top*sizeof(BN_ULONG)));

		BN_bin2bn(static_cast<u8_t *>(&(out[ind*BLOCK_SIZE])), BLOCK_SIZE, &bn_xj);

		// xkey = (tmp + xj) % mod
		BN_mod_add(&bn_xkey, &bn_tmp, &bn_xj, &bn_mod, ctx);

		BN_bn2bin(&bn_xkey, static_cast<u8_t *>(tmp_xkey));

		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("dss_pseudo_random(): xkey[%d] = (tmp + x[%d]) % mod\n"),
			ind+1u,
			ind));
		EAP_TRACE_FORMAT(m_am_tools, (debug_buffer, DEBUG_BUFFER_SIZE, EAPL("xkey[%d]"), ind+1u));
		EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (reinterpret_cast<eap_format_string>(debug_buffer),
			tmp_xkey, sizeof(tmp_xkey)));
	}

	CLEAN_OPENSSL_BN(ctx);

	return eap_status_ok;
}

// End.
