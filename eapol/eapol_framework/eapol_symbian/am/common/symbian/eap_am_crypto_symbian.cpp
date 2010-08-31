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
	#define EAP_FILE_NUMBER_ENUM 145 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDES
#include <hash.h>
#include <random.h>
#include <asymmetric.h>
#include <symmetric.h>
#include <rijndael.h>

#include <x509keys.h>
#include <asn1dec.h>
#include <asn1enc.h>

#include "eap_am_crypto_symbian.h"
#include "eap_tools.h"
#include "eap_am_tools_symbian.h"
#include "dss_random.h"

#include "eap_am_crypto_sha_256.h"
#include "eap_am_crypto_sha1.h"
#include "eap_am_crypto_rc4.h"
#include "eap_am_crypto_md4.h"

#include "eap_am_memory.h"
#include "eap_am_assert.h"

// LOCAL DATA
const u32_t BLOCK_SIZE_3DES_EDE = 8ul;
const u32_t MD5_BLOCK_SIZE = 64ul;
const u32_t AES_KEY_SIZE = 16ul;
const u32_t AES_BLOCK_SIZE = 16ul;

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_crypto_symbian_c::~eap_am_crypto_symbian_c()
{
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_am_crypto_symbian_c::eap_am_crypto_symbian_c(abs_eap_am_tools_c * const tools)
	: m_am_tools(tools)
	, m_is_valid(false)
{
	m_is_valid = true;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT bool eap_am_crypto_symbian_c::get_is_valid() const
{
	return m_is_valid;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_crypto_symbian_c::set_is_valid()
{
	m_is_valid = true;
}
	
//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::configure()
{
	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT void eap_am_crypto_symbian_c::use_test_random(
	const u8_t * const /* seed */,
	const u32_t /* seed_length */,
	const bool /* does_continuous_seeding_when_true */)
{
	// This does nothing yet. Later we may need test random generator.
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::add_rand_seed(
	const u8_t * const /* bytes */, const u32_t /* length */)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::add_rand_seed_hw_ticks()
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	u64_t ticks = m_am_tools->get_hardware_ticks();
	u8_t entropy_bits = static_cast<u8_t>(ticks & 0xff);
	add_rand_seed(
		reinterpret_cast<u8_t *>(&entropy_bits),
		sizeof(entropy_bits));
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}

//--------------------------------------------------

//
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::get_rand_bytes(
	u8_t * const bytes,
	const u32_t length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	TPtr8 target(bytes, length, length);

	TRandom::Random(target);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}


EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::generate_diffie_hellman_keys(
	eap_variable_data_c * const own_private_dh_key,
	eap_variable_data_c * const own_public_dh_key,
	const u8_t * const prime,
	const u32_t prime_length,
	const u8_t * const group_generator,
	const u32_t group_generator_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	
	eap_status_e status = eap_status_ok;
	TRAPD(err, generate_diffie_hellman_keysL(
		own_private_dh_key,
		own_public_dh_key,
		prime,
		prime_length,
		group_generator,
		group_generator_length));
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_crypto_symbian_c::generate_diffie_hellman_keysL(
	eap_variable_data_c * const own_private_dh_key,
	eap_variable_data_c * const own_public_dh_key,
	const u8_t * const prime,
	const u32_t prime_length,
	const u8_t * const group_generator,
	const u32_t group_generator_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	eap_status_e status;

	TPtrC8 _prime(prime, prime_length);
	TPtrC8 _generator(group_generator, group_generator_length);
	
	RInteger N = RInteger::NewL(_prime);
	CleanupStack::PushL(N);
	
	RInteger G = RInteger::NewL(_generator);
	CleanupStack::PushL(G);	
	
	CDHKeyPair* dh_key = CDHKeyPair::NewL(N, G);
	CleanupStack::Pop(&G); // N, G
	CleanupStack::Pop(&N); // N, G

	CleanupStack::PushL(dh_key);
	
	const CDHPublicKey& publicKey = dh_key->PublicKey();
	
	const TInteger& X = publicKey.X();
	
	HBufC8* p = X.BufferLC();
	// Copy the public key
	status = own_public_dh_key->set_copy_of_buffer(p->Des().Ptr(), p->Length());
	if (status != eap_status_ok)
	{
		User::Leave(KErrNoMemory);
	}
	CleanupStack::PopAndDestroy(p); 


	const CDHPrivateKey& privateKey = dh_key->PrivateKey();
	
	const TInteger& x = privateKey.x();
	
	p = x.BufferLC();
	// Copy the private key
	status = own_private_dh_key->set_copy_of_buffer(p->Des().Ptr(), p->Length());
	if (status != eap_status_ok)
	{
		User::Leave(KErrNoMemory);
	}
	CleanupStack::PopAndDestroy(p); 

	CleanupStack::PopAndDestroy(dh_key);			

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("own_public_dh_key"),
		own_public_dh_key->get_data(own_public_dh_key->get_data_length()),
		own_public_dh_key->get_data_length()));

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("own_private_dh_key is hidden in Symbian.\n")));
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::generate_g_power_to_xy(
	const eap_variable_data_c * const own_private_dh_key,
	const eap_variable_data_c * const peer_public_dh_key,
	eap_variable_data_c * const shared_dh_key,
	const u8_t * const prime,
	const u32_t prime_length,
	const u8_t * const group_generator,
	const u32_t group_generator_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	
	eap_status_e status = eap_status_ok;
	TRAPD(err, generate_g_power_to_xyL(
		own_private_dh_key,
		peer_public_dh_key,
		shared_dh_key,
		prime,
		prime_length,
		group_generator,
		group_generator_length));
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

void eap_am_crypto_symbian_c::generate_g_power_to_xyL(
	const eap_variable_data_c * const own_private_dh_key,
	const eap_variable_data_c * const peer_public_dh_key,
	eap_variable_data_c * const shared_dh_key,
	const u8_t * const prime,
	const u32_t prime_length,
	const u8_t * const group_generator,
	const u32_t group_generator_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	eap_status_e status(eap_status_ok);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("peer_public_dh_key"),
		peer_public_dh_key->get_data(peer_public_dh_key->get_data_length()),
		peer_public_dh_key->get_data_length()));

	
	// PUBLIC KEY
	TPtrC8 peer_key(
		peer_public_dh_key->get_data(peer_public_dh_key->get_data_length()), 
		peer_public_dh_key->get_data_length());
	if (peer_key.Ptr() == 0)
	{
		User::Leave(KErrArgument);
	}

	RInteger Y = RInteger::NewL(peer_key);
	CleanupStack::PushL(Y); 
	
	
	TPtrC8 peer_prime(
		prime, 
		prime_length);
	if (peer_prime.Ptr() == 0)
	{
		User::Leave(KErrArgument);
	}

	RInteger N = RInteger::NewL(peer_prime);
	CleanupStack::PushL(N); 

	TPtrC8 peer_generator(
		group_generator, 
		group_generator_length);
	if (peer_prime.Ptr() == 0)
	{
		User::Leave(KErrArgument);
	}
	
	RInteger G = RInteger::NewL(peer_generator);
	CleanupStack::PushL(G); 

	CDHPublicKey* publicKey = CDHPublicKey::NewL(N, G, Y);
	CleanupStack::Pop(&G); // The parameters are freed by CDHPublicKey
	CleanupStack::Pop(&N); // The parameters are freed by CDHPublicKey
	CleanupStack::Pop(&Y); // The parameters are freed by CDHPublicKey
	CleanupStack::PushL(publicKey);

	// PRIVATE KEY
	RInteger Npriv = RInteger::NewL(peer_prime);
	CleanupStack::PushL(Npriv);
	
	RInteger Gpriv = RInteger::NewL(peer_generator); // !
	CleanupStack::PushL(Gpriv);
	
	TPtrC8 private_key(
		own_private_dh_key->get_data(own_private_dh_key->get_data_length()), 
		own_private_dh_key->get_data_length());
	if (private_key.Ptr() == 0)
	{
		User::Leave(KErrArgument);
	}
	RInteger x = RInteger::NewL(private_key);
	CleanupStack::PushL(x); 
	
	CDHPrivateKey* privateKey = CDHPrivateKey::NewL(Npriv, Gpriv, x);
	CleanupStack::Pop(&x);
	CleanupStack::Pop(&Gpriv);
	CleanupStack::Pop(&Npriv);
	CleanupStack::PushL(privateKey);
	
	CDH* dh = CDH::NewL(*privateKey);
	CleanupStack::PushL(dh);

	// Have to do const_cast so that the object can be pushed... strange...
	HBufC8* p = const_cast<HBufC8*>(dh->AgreeL(*publicKey));
	CleanupStack::PushL(p);

	// Copy the shared key
	status = shared_dh_key->set_copy_of_buffer(const_cast<HBufC8*>(p)->Des().Ptr(), p->Length());
	if (status != eap_status_ok)
	{		
		User::Leave(KErrNoMemory);
	}

	CleanupStack::PopAndDestroy(p);  // p, dh, publicKey, privateKey
	CleanupStack::PopAndDestroy(dh);  // p, dh, publicKey, privateKey
	CleanupStack::PopAndDestroy(privateKey);  // p, dh, publicKey, privateKey
	CleanupStack::PopAndDestroy(publicKey);  // p, dh, publicKey, privateKey
	
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("     shared_dh_key"),
		shared_dh_key->get_data(shared_dh_key->get_data_length()),
		shared_dh_key->get_data_length()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::dh_cleanup(
		const eap_variable_data_c * const /*dh_context*/)
{	
	return eap_status_ok;
}

//--------------------------------------------------


EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_sha_256_digest_length(
	eap_variable_data_c * const sha_256_context)
{
	eap_am_crypto_sha_256_c * const sha_256 = reinterpret_cast<eap_am_crypto_sha_256_c *>(
		sha_256_context->get_data(sizeof(eap_am_crypto_sha_256_c * const)));
	if (sha_256 == 0
		|| sha_256->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	return sha_256->get_digest_length();
}

//--------------------------------------------------


EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_sha_256_block_size(
	eap_variable_data_c * const sha_256_context)
{
	eap_am_crypto_sha_256_c * const sha_256 = reinterpret_cast<eap_am_crypto_sha_256_c *>(
		sha_256_context->get_data(sizeof(eap_am_crypto_sha_256_c * const)));
	if (sha_256 == 0
		|| sha_256->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	return sha_256->get_block_size();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha_256_init(
	eap_variable_data_c * const sha_256_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	eap_am_crypto_sha_256_c * sha_256 = 0;

	if (sha_256_context->get_is_valid_data() == true)
	{
		sha_256 = reinterpret_cast<eap_am_crypto_sha_256_c *>(
			sha_256_context->get_data(sizeof(eap_am_crypto_sha_256_c * const)));
		if (sha_256 == 0
			|| sha_256->get_is_valid() == false)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		}
	}

	eap_status_e status = eap_status_process_general_error;

	if (sha_256 == 0)
	{
		sha_256 = new eap_am_crypto_sha_256_c(m_am_tools);
		if (sha_256 == 0
			|| sha_256->get_is_valid() == false)
		{
			delete sha_256;
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = sha_256_context->set_buffer(sha_256, sizeof(sha_256), false, true);
		if (status != eap_status_ok)
		{
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = sha_256->hash_init();
	if (status != eap_status_ok)
	{
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha_256_update(
	eap_variable_data_c * const sha_256_context,
	const u8_t * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(sha_256_context->get_is_valid_data() == true);

	eap_am_crypto_sha_256_c * const sha_256 = reinterpret_cast<eap_am_crypto_sha_256_c *>(
		sha_256_context->get_data(sizeof(eap_am_crypto_sha_256_c * const)));
	if (sha_256 == 0
		|| sha_256->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = sha_256->hash_update(
		data,
		data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_am_crypto_symbian_c::sha_256_update(), failed status = %d\n"),
			 status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha_256_final(
	eap_variable_data_c * const sha_256_context,
	u8_t * const message_digest,
	u32_t *md_length_or_null)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(sha_256_context->get_is_valid_data() == true);

	eap_am_crypto_sha_256_c * const sha_256 = reinterpret_cast<eap_am_crypto_sha_256_c *>(
		sha_256_context->get_data(sizeof(eap_am_crypto_sha_256_c * const)));
	if (sha_256 == 0
		|| sha_256->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = sha_256->hash_final(
		message_digest,
		md_length_or_null);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_DEFAULT,
			(EAPL("ERROR: eap_am_crypto_symbian_c::sha_256_final(), failed status = %d\n"),
			 status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha_256_cleanup(
	eap_variable_data_c * const sha_256_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(sha_256_context->get_is_valid_data() == true);

	eap_am_crypto_sha_256_c * const sha_256 = reinterpret_cast<eap_am_crypto_sha_256_c *>(
		sha_256_context->get_data(sizeof(eap_am_crypto_sha_256_c * const)));
	if (sha_256 == 0
		|| sha_256->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	}

	delete sha_256;

	sha_256_context->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha_256_copy_context(
	eap_variable_data_c * const copied_sha_256_context,
	const eap_variable_data_c * const original_sha_256_context)
{
	eap_am_crypto_sha_256_c * const sha_256 = reinterpret_cast<eap_am_crypto_sha_256_c *>(
		original_sha_256_context->get_data(sizeof(eap_am_crypto_sha_256_c * const)));
	if (sha_256 == 0
		|| sha_256->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_sha_256_c * const sha_256_copy = sha_256->copy();
	if (sha_256_copy == 0
		|| sha_256_copy->get_is_valid() == false)
	{
		delete sha_256_copy;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = copied_sha_256_context->set_buffer(sha_256_copy, sizeof(sha_256_copy), false, true);

	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_sha1_digest_length(
	eap_variable_data_c * const sha1_context)
{
	eap_am_crypto_sha1_c * const sha1 = reinterpret_cast<eap_am_crypto_sha1_c *>(
		sha1_context->get_data(sizeof(eap_am_crypto_sha1_c)));

	if (sha1 == 0
		|| sha1->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	return sha1->get_digest_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_sha1_block_size(
	eap_variable_data_c * const sha1_context)
{
	eap_am_crypto_sha1_c * const sha1 = reinterpret_cast<eap_am_crypto_sha1_c *>(
		sha1_context->get_data(sizeof(eap_am_crypto_sha1_c)));

	if (sha1 == 0
		|| sha1->get_is_valid() == false)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	return sha1->get_block_size();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha1_init(
	eap_variable_data_c * const sha1_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	eap_status_e status = eap_status_process_general_error;

	eap_am_crypto_sha1_c * sha1 = 0;

	if (sha1_context->get_is_valid_data() == true)
	{
		sha1 = reinterpret_cast<eap_am_crypto_sha1_c *>(
			sha1_context->get_data(sizeof(eap_am_crypto_sha1_c)));

		if (sha1 != 0
			&& sha1->get_is_valid() == false)
		{
			// Delete old invalid context.
			status = sha1_cleanup(sha1_context);
			if (status != eap_status_ok)
			{
				EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
				return EAP_STATUS_RETURN(m_am_tools, status);
			}

			// Next we allocate new context.
			sha1 = 0;
		}
	
	}
	else
	{
		// There are no context.
		// We will allocate a new one.
	}

	if (sha1 == 0)
	{
		sha1 = new eap_am_crypto_sha1_c(m_am_tools);
		if (sha1 == 0
			|| sha1->get_is_valid() == false)
		{
			delete sha1;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
			return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
		}

		status = sha1_context->set_buffer(sha1, sizeof(*sha1), false, true);
		if (status != eap_status_ok)
		{
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = sha1->hash_init();
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha1_update(
	eap_variable_data_c * const sha1_context,
	const u8_t * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	eap_am_crypto_sha1_c * const sha1 = reinterpret_cast<eap_am_crypto_sha1_c *>(
		sha1_context->get_data(sizeof(eap_am_crypto_sha1_c)));

	if (sha1 == 0
		|| sha1->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = sha1->hash_update(
		data,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha1_final(
	eap_variable_data_c * const sha1_context,
	u8_t * const message_digest,
	u32_t *md_length_or_null)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	eap_am_crypto_sha1_c * const sha1 = reinterpret_cast<eap_am_crypto_sha1_c *>(
		sha1_context->get_data(sizeof(eap_am_crypto_sha1_c)));

	if (sha1 == 0
		|| sha1->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

    eap_status_e status = sha1->hash_final(
		message_digest,
		md_length_or_null);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha1_cleanup(
	eap_variable_data_c * const sha1_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(sha1_context != 0);
	EAP_ASSERT(sha1_context->get_is_valid() == true);
	if (sha1_context == 0
		|| sha1_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_sha1_c * const sha1 = reinterpret_cast<eap_am_crypto_sha1_c *>(
		sha1_context->get_data(sizeof(eap_am_crypto_sha1_c)));

	delete sha1;

	sha1_context->reset();
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::sha1_copy_context(
	eap_variable_data_c * const copied_sha1_context,
	const eap_variable_data_c * const original_sha1_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	eap_am_crypto_sha1_c * const sha1 = reinterpret_cast<eap_am_crypto_sha1_c *>(
		original_sha1_context->get_data(sizeof(eap_am_crypto_sha1_c)));

	if (sha1 == 0
		|| sha1->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_sha1_c * const sha1_copy = sha1->copy();

	if (sha1_copy == 0
		|| sha1_copy->get_is_valid() == false)
	{
		delete sha1_copy;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = copied_sha1_context->set_buffer(sha1_copy, sizeof(*sha1_copy), false, true);

	if (status != eap_status_ok)
	{
		delete sha1_copy;
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::aes_key_length()
{
	return AES_KEY_SIZE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::aes_block_size()
{
	return AES_BLOCK_SIZE;
}


//--------------------------------------------------

// NOTE ::dss_pseudo_random is implemented in am/common/DSS_random/dss_random.cpp.
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::dss_pseudo_random(
	u8_t *out,
	u32_t out_length,
	u8_t *xkey,
	u32_t xkey_length)
{
	eap_status_e status = ::dss_pseudo_random(m_am_tools, out, out_length, xkey, xkey_length);
	return status;
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_crypto_symbian_c::open_crypto_memory_leaks()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT void eap_am_crypto_symbian_c::close_crypto_memory_leaks()
{
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rc4_set_key(eap_variable_data_c * const rc4_context, 
																const eap_variable_data_c * const key)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	if (key == 0
		|| key->get_is_valid_data() == false
		|| key->get_data_length() == 0
		|| rc4_context == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_rc4_c * const rc4 = new eap_am_crypto_rc4_c(m_am_tools);
	if (rc4 == 0
		|| rc4->get_is_valid() == false)
	{
		delete rc4;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = rc4->set_key(key);
	if (status != eap_status_ok)
	{
		delete rc4;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (rc4_context->get_is_valid_data() == true)
	{
		status = rc4_cleanup(rc4_context);
		if (status != eap_status_ok)
		{
			delete rc4;
			EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
			return EAP_STATUS_RETURN(m_am_tools, status);
		}
	}

	status = rc4_context->set_buffer(rc4, sizeof(*rc4), false, true);
	if (status != eap_status_ok)
	{
		delete rc4;		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rc4_cleanup(
	eap_variable_data_c * const rc4_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	EAP_ASSERT(rc4_context != 0);
	EAP_ASSERT(rc4_context->get_is_valid() == true);
	if (rc4_context == 0
		|| rc4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_rc4_c * const rc4 = reinterpret_cast<eap_am_crypto_rc4_c *>(
		rc4_context->get_data(sizeof(eap_am_crypto_rc4_c)));
	
	delete rc4;

	rc4_context->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rc4_encrypt(
	const eap_variable_data_c * const rc4_context,
	void * const data_in_out,
	const u32_t data_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(rc4_context != 0);
	EAP_ASSERT(rc4_context->get_is_valid() == true);
	if (rc4_context == 0
		|| rc4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_rc4_c * const rc4 = reinterpret_cast<eap_am_crypto_rc4_c *>(
		rc4_context->get_data(sizeof(eap_am_crypto_rc4_c)));
	
	if (rc4 == 0
		|| rc4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	eap_status_e status = rc4->encrypt_data(
		data_in_out,
		data_in_out,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rc4_encrypt(
	const eap_variable_data_c * const rc4_context,
	const void * const data_in, 
	void * const data_out,
	const u32_t data_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(rc4_context != 0);
	EAP_ASSERT(rc4_context->get_is_valid() == true);
	if (rc4_context == 0
		|| rc4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_rc4_c * const rc4 = reinterpret_cast<eap_am_crypto_rc4_c *>(
		rc4_context->get_data(sizeof(eap_am_crypto_rc4_c)));

	if (rc4 == 0
		|| rc4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	eap_status_e status = rc4->encrypt_data(
		data_in,
		data_out,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rc4_decrypt(
	const eap_variable_data_c * const rc4_context,
	void * const data_in_out,
	const u32_t data_length)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(rc4_context != 0);
	EAP_ASSERT(rc4_context->get_is_valid() == true);
	if (rc4_context == 0
		|| rc4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_rc4_c * const rc4 = reinterpret_cast<eap_am_crypto_rc4_c *>(
		rc4_context->get_data(sizeof(eap_am_crypto_rc4_c)));

	if (rc4 == 0
		|| rc4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	eap_status_e status = rc4->decrypt_data(
		data_in_out,
		data_in_out,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rc4_decrypt(
	const eap_variable_data_c * const rc4_context,
	const void * const data_in, 
	void * const data_out,
	const u32_t data_length)
{		
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(rc4_context != 0);
	EAP_ASSERT(rc4_context->get_is_valid() == true);
	if (rc4_context == 0
		|| rc4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_rc4_c * const rc4 = reinterpret_cast<eap_am_crypto_rc4_c *>(
		rc4_context->get_data(sizeof(eap_am_crypto_rc4_c)));

	if (rc4 == 0
		|| rc4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	eap_status_e status = rc4->decrypt_data(
		data_in,
		data_out,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_init(
		eap_variable_data_c * const rsa_context)
{
	EAP_UNREFERENCED_PARAMETER(rsa_context);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	eap_status_e status = rsa_context->init(0);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}
	
	rsa_context->set_is_valid(); 		
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_encrypt_with_public_key(
	eap_variable_data_c * const rsa_context,
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_key(), begins.\n")));

	eap_status_e status = eap_status_ok;
	
	TRAPD(err, rsa_encrypt_with_public_keyL(
		rsa_context,
		public_rsa_key,
		input_data,
		output_data));
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_key() failed, status %d.\n"),
			status));
	} 
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


void eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL(), begins.\n")));

	TPtrC8 ptr(
		public_rsa_key->get_data(public_rsa_key->get_data_length()), 
		public_rsa_key->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, public_rsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	// The public_rsa_key is ASN.1 encoded.
	// SEQUENCE {
	//	  INTEGER modulus
	//	  INTEGER exponent
	// }
	//
	//
	TASN1DecSequence seq;
	TASN1DecInteger asn1;
	TASN1DecGeneric* gen;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL(), before DecodeDERLC().\n")));

	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	TInt pos(0);
	arrayPtr = seq.DecodeDERLC(ptr, pos);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(0);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 m = gen->Encoding();			
	if (m.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	pos = 0;
	RInteger modulus = asn1.DecodeDERLongL(m, pos);
	CleanupStack::PushL(modulus);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 e = gen->Encoding();			
	if (e.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	pos = 0;
	RInteger exponent = asn1.DecodeDERLongL(e, pos);
	CleanupStack::PushL(exponent);

	TPtrC8 input(
		input_data->get_data(input_data->get_data_length()), 
		input_data->get_data_length());
	if (input.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, input_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	// The length of the ciphertext in RSA is the next multiple of block size. 
	TUint output_data_length = ((input_data->get_data_length() / modulus.ByteCount()) + 1) * modulus.ByteCount();
	eap_status_e status = output_data->init(output_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, output_data is invalid, status %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrNoMemory);
	}

	output_data->set_is_valid();
	output_data->set_data_length(output_data_length);
	TPtr8 output(
		output_data->get_data(output_data->get_data_length()), 
		output_data->get_data_length());
	if (output.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL() failed, output_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	
	CRSAPublicKey* public_key = CRSAPublicKey::NewL(modulus, exponent);
	CleanupStack::Pop(&exponent); // Exponent, modulus are freed by CRSAPublicKey
	CleanupStack::Pop(&modulus); // Exponent, modulus are freed by CRSAPublicKey
	CleanupStack::PushL(public_key);

	CRSAPKCS1v15Encryptor* rsa_encryptor = CRSAPKCS1v15Encryptor::NewL(*public_key);
	CleanupStack::PushL(rsa_encryptor);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL(), before EncryptL().\n")));

	rsa_encryptor->EncryptL(input, output);
	
	output_data->set_data_length(output.Length());

	CleanupStack::PopAndDestroy(rsa_encryptor);
	CleanupStack::PopAndDestroy(public_key);
	CleanupStack::PopAndDestroy(arrayPtr);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_public_keyL(), OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_decrypt_with_public_key(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const /*public_rsa_key*/,
	const eap_variable_data_c * const /*input_data*/,
	eap_variable_data_c * const /*output_data*/)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_key(), begins.\n")));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}

void eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL(), begins.\n")));

	TPtrC8 ptr(
		public_rsa_key->get_data(public_rsa_key->get_data_length()), 
		public_rsa_key->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, public_rsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	// The public_rsa_key is ASN.1 encoded.
	// SEQUENCE {
	//	  INTEGER modulus
	//	  INTEGER exponent
	// }
	//
	//
	TASN1DecSequence seq;
	TASN1DecInteger asn1;
	TASN1DecGeneric* gen;
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL(), before DecodeDERLC().\n")));

	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	TInt pos(0);
	arrayPtr = seq.DecodeDERLC(ptr, pos);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(0);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 m = gen->Encoding();			
	if (m.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	pos = 0;
	RInteger modulus = asn1.DecodeDERLongL(m, pos);
	CleanupStack::PushL(modulus);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 e = gen->Encoding();			
	if (e.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	pos = 0;
	RInteger exponent = asn1.DecodeDERLongL(e, pos);
	CleanupStack::PushL(exponent);

	TPtrC8 input(
		input_data->get_data(input_data->get_data_length()), 
		input_data->get_data_length());
	if (input.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, input_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	// The length of the plaintext is equal or less than the ciphertext length.
	TUint output_data_length = input_data->get_data_length();
	eap_status_e status = output_data->init(output_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, output_data is invalid, status %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrNoMemory);
	}
	output_data->set_is_valid();
	output_data->set_data_length(output_data_length);

	TPtr8 output(
		output_data->get_data(output_data->get_data_length()), 
		output_data->get_data_length());
	if (output.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL() failed, output_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	// The key is actually public key but the class still needs to be CRSAPrivateKey for decryption
	CleanupStack::Pop(&exponent); // Next class frees the integers
	CleanupStack::Pop(&modulus); // Next class frees the integers
	
	CRSAPrivateKeyStandard* public_key = CRSAPrivateKeyStandard::NewL(modulus, exponent);
	CleanupStack::PushL(public_key);

	CRSAPKCS1v15Decryptor* rsa_decryptor = CRSAPKCS1v15Decryptor::NewL(*public_key);
	CleanupStack::PushL(rsa_decryptor);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL(), before DecryptL().\n")));

	rsa_decryptor->DecryptL(input, output);
	
	// Set the real data length
	output_data->set_data_length(output.Length());

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_public_keyL(), OK.\n")));

	CleanupStack::PopAndDestroy(rsa_decryptor);
	CleanupStack::PopAndDestroy(public_key);
	CleanupStack::PopAndDestroy(arrayPtr);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
}

//--------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_encrypt_with_private_key(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const /*private_rsa_key*/,
	const eap_variable_data_c * const /*input_data*/,
	eap_variable_data_c * const /*output_data*/)
{
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_key(), begins.\n")));

	return EAP_STATUS_RETURN(m_am_tools, eap_status_not_supported);
}


void eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL(), begins.\n")));

	TPtrC8 ptr(
		private_rsa_key->get_data(private_rsa_key->get_data_length()), 
		private_rsa_key->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, private_rsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	// The private_rsa_key is ASN.1 encoded.
	// SEQUENCE {
	//	  INTEGER modulus
	//	  INTEGER public_exponent
	//	  INTEGER private_exponent
	//    ...
	// }
	//
	//
	TASN1DecSequence seq;
	TASN1DecInteger asn1;
	TASN1DecGeneric* gen;
	
	RInteger modulus;
	RInteger private_exponent;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL(), before DecodeDERLC().\n")));

	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	TInt pos(0);
	arrayPtr = seq.DecodeDERLC(ptr, pos);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 m = gen->Encoding();			
	if (m.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	modulus = asn1.DecodeDERLongL(m, pos);
	CleanupStack::PushL(modulus);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(3);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 priv_e = gen->Encoding();			
	if (priv_e.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	private_exponent = asn1.DecodeDERLongL(priv_e, pos);
	CleanupStack::PushL(private_exponent);

	TPtrC8 input(
		input_data->get_data(input_data->get_data_length()), 
		input_data->get_data_length());
	if (input.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, input_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	// The length of the ciphertext in RSA is the next multiple of block size. 
	TUint output_data_length = ((input_data->get_data_length() / modulus.ByteCount()) + 1) * modulus.ByteCount();
	eap_status_e status = output_data->init(output_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, output_data is invalid, status %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrNoMemory);
	}
	output_data->set_is_valid();
	output_data->set_data_length(output_data_length);

	TPtr8 output(
		output_data->get_data(output_data->get_data_length()), 
		output_data->get_data_length());
	if (output.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL() failed, output_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	CleanupStack::Pop(&private_exponent); // private exponent & modulus are freed by the next class
	CleanupStack::Pop(&modulus); // private exponent & modulus are freed by the next class
	CRSAPublicKey* private_key = CRSAPublicKey::NewL(modulus, private_exponent);
	CleanupStack::PushL(private_key);

	CRSAPKCS1v15Encryptor* rsa_encryptor = CRSAPKCS1v15Encryptor::NewL(*private_key);
	CleanupStack::PushL(rsa_encryptor);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL(), before EncryptL().\n")));

	rsa_encryptor->EncryptL(input, output);
	
	output_data->set_data_length(output.Length());

	CleanupStack::PopAndDestroy(rsa_encryptor);
	CleanupStack::PopAndDestroy(private_key);
	CleanupStack::PopAndDestroy(arrayPtr);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_encrypt_with_private_keyL(), OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
}

//--------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_decrypt_with_private_key(
	eap_variable_data_c * const rsa_context,
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_key(), begins.\n")));

	eap_status_e status = eap_status_ok;
	TRAPD(err, rsa_decrypt_with_private_keyL(
		rsa_context,
		private_rsa_key,
		input_data,
		output_data));
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_key() failed, err %d, status %d.\n"),
			err,
			status));
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}


void eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const input_data,
	eap_variable_data_c * const output_data)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL(), begins.\n")));

	TPtrC8 ptr(
		private_rsa_key->get_data(private_rsa_key->get_data_length()), 
		private_rsa_key->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, private_rsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	// The private_rsa_key is ASN.1 encoded.
	// SEQUENCE {
	//	  INTEGER modulus
	//	  INTEGER public_exponent
	//	  INTEGER private_exponent
	//    ...
	// }
	//
	//
	TASN1DecSequence seq;
	TASN1DecInteger asn1;
	TASN1DecGeneric* gen;
	RInteger modulus;
	RInteger private_exponent;
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL(), before DecodeDERLC().\n")));

	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	TInt pos(0);
	arrayPtr = seq.DecodeDERLC(ptr, pos);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 m = gen->Encoding();			
	if (m.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	pos = 0;
	modulus = asn1.DecodeDERLongL(m, pos);
	CleanupStack::PushL(modulus);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(3);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 priv_e = gen->Encoding();			
	if (priv_e.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	private_exponent = asn1.DecodeDERLongL(priv_e, pos);
	CleanupStack::PushL(private_exponent);

	TPtrC8 input(
		input_data->get_data(input_data->get_data_length()), 
		input_data->get_data_length());
	if (input.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, input_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	// The length of the plaintext is equal or less than the ciphertext length.
	TUint output_data_length = input_data->get_data_length();
	eap_status_e status = output_data->init(output_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, output_data is invalid, status %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrNoMemory);
	}
	output_data->set_is_valid();
	output_data->set_data_length(output_data_length);

	TPtr8 output(
		output_data->get_data(output_data->get_data_length()), 
		output_data->get_data_length());
	if (output.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL() failed, output_data is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	

	CRSAPrivateKey* private_key = CRSAPrivateKeyStandard::NewL(modulus, private_exponent);

	CleanupStack::Pop(&private_exponent); // modulus & private_exponent are freed CRSAPrivateKey
	CleanupStack::Pop(&modulus); // modulus & private_exponent are freed CRSAPrivateKey
	CleanupStack::PushL(private_key);

	CRSAPKCS1v15Decryptor* rsa_decryptor = CRSAPKCS1v15Decryptor::NewL(*private_key);
	CleanupStack::PushL(rsa_decryptor);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL(), before DecryptL().\n")));

	rsa_decryptor->DecryptL(input, output);
	
	// Now set the correct length
	output_data->set_data_length(output.Length());

	CleanupStack::PopAndDestroy(rsa_decryptor);
	CleanupStack::PopAndDestroy(private_key);
	CleanupStack::PopAndDestroy(arrayPtr);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_decrypt_with_private_keyL(), OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
}

//--------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_sign(
	eap_variable_data_c * const rsa_context,
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const hash,
	eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_sign(), begins.\n")));

	eap_status_e status = eap_status_ok;

	TRAPD(err, rsa_signL(
		rsa_context,
		private_rsa_key,
		hash,
		signed_hash));
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_sign() failed, err %d, status %d.\n"),
			err,
			status));
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_am_crypto_symbian_c::rsa_signL(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const private_rsa_key,
	const eap_variable_data_c * const hash,
	eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_signL(), begins.\n")));

	TPtrC8 ptr(
		private_rsa_key->get_data(private_rsa_key->get_data_length()), 
		private_rsa_key->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, private_rsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	// The private_rsa_key is ASN.1 encoded.
	// SEQUENCE {
	//	  INTEGER modulus
	//	  INTEGER public_exponent
	//	  INTEGER private_exponent
	//    ...
	// }
	//
	//
	TASN1DecSequence seq;
	TASN1DecInteger asn1;
	TASN1DecGeneric* gen;
	
	RInteger modulus;
	RInteger private_exponent;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_signL(), before DecodeDERLC().\n")));

	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	TInt pos(0);
	arrayPtr = seq.DecodeDERLC(ptr, pos);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_signL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 m = gen->Encoding();			
	if (m.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	pos = 0;
	modulus = asn1.DecodeDERLongL(m, pos);
	CleanupStack::PushL(modulus);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_signL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(3);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 priv_e = gen->Encoding();			
	if (priv_e.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	private_exponent = asn1.DecodeDERLongL(priv_e, pos);
	CleanupStack::PushL(private_exponent);

	TPtrC8 input(
		hash->get_data(hash->get_data_length()), 
		hash->get_data_length());
	if (input.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, hash is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	// The length of the ciphertext in RSA is the next multiple of block size. 
	TUint output_data_length = ((hash->get_data_length() / modulus.ByteCount()) + 1) * modulus.ByteCount();

	eap_status_e status = signed_hash->init(output_data_length);
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, signed_hash is invalid, status %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrNoMemory);
	}
	signed_hash->set_is_valid();
	signed_hash->set_data_length(output_data_length);

	TPtr8 output(
		signed_hash->get_data(signed_hash->get_data_length()), 
		signed_hash->get_data_length());
	if (output.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_signL() failed, signed_hash is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	CleanupStack::Pop(&private_exponent); // private exponent & modulus are freed by the next class
	CleanupStack::Pop(&modulus); // private exponent & modulus are freed by the next class
	CRSAPrivateKeyStandard* private_key = CRSAPrivateKeyStandard::NewL(modulus, private_exponent);
	CleanupStack::PushL(private_key);

	CRSAPKCS1v15Signer* rsa_signer = CRSAPKCS1v15Signer::NewL(*private_key);	
	CleanupStack::PushL(rsa_signer);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_signL(), before SignL().\n")));

	const CRSASignature* signature = rsa_signer->SignL(input);
	const TInteger& sig = signature->S();

	HBufC8* buf = sig.BufferLC();

	output.Copy(*buf);
	signed_hash->set_data_length(output.Length());
	
	CleanupStack::PopAndDestroy(buf);
	CleanupStack::PopAndDestroy(rsa_signer);
	CleanupStack::PopAndDestroy(private_key);
	CleanupStack::PopAndDestroy(arrayPtr);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_signL(), OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_verify(
	eap_variable_data_c * const rsa_context,
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const hash,
	const eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_verify(), begins.\n")));

	eap_status_e status = eap_status_ok;

	TRAPD(err, rsa_verifyL(
		rsa_context,
		public_rsa_key,
		hash,
		signed_hash));
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verify() failed, err %d, status %d.\n"),
			err,
			status));
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

eap_status_e eap_am_crypto_symbian_c::rsa_verifyL(
	eap_variable_data_c * const /*rsa_context*/,
	const eap_variable_data_c * const public_rsa_key,
	const eap_variable_data_c * const hash,
	const eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	
	TPtrC8 ptr(
		public_rsa_key->get_data(public_rsa_key->get_data_length()), 
		public_rsa_key->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verifyL() failed, public_rsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	// The public_rsa_key is ASN.1 encoded.
	// SEQUENCE {
	//	  INTEGER modulus
	//	  INTEGER exponent
	// }
	//
	//
	TASN1DecSequence seq;
	TASN1DecInteger asn1;
	TASN1DecGeneric* gen;
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_verifyL(), before DecodeDERLC().\n")));

	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	TInt pos(0);
	arrayPtr = seq.DecodeDERLC(ptr, pos);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_verifyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(0);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verifyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 m = gen->Encoding();			
	if (m.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verifyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	RInteger modulus = asn1.DecodeDERLongL(m, pos);
	CleanupStack::PushL(modulus);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_verifyL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verifyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 e = gen->Encoding();			
	if (e.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verifyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	RInteger exponent = asn1.DecodeDERLongL(e, pos);
	CleanupStack::PushL(exponent);

	TPtrC8 p_hash(
		hash->get_data(hash->get_data_length()), 
		hash->get_data_length());
	if (p_hash.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verifyL() failed, hash is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	
	TPtrC8 p_sig(
		signed_hash->get_data(signed_hash->get_data_length()), 
		signed_hash->get_data_length());
	if (p_sig.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::rsa_verifyL() failed, signed_hash is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	
	CRSAPublicKey* public_key = CRSAPublicKey::NewL(modulus, exponent);
	// Modulus and exponent are popped here because CRSAPublicKey frees them
	CleanupStack::Pop(&exponent);
	CleanupStack::Pop(&modulus);
	CleanupStack::PushL(public_key);

	RInteger signature = RInteger::NewL(p_sig);
	CleanupStack::PushL(signature);

	CRSASignature* rsa_signature = CRSASignature::NewL(signature);	
	// signature is popped here because CRSASignature frees it
	CleanupStack::Pop(&signature);
	CleanupStack::PushL(rsa_signature);	

	
	CRSAPKCS1v15Verifier* rsa_verifier = CRSAPKCS1v15Verifier::NewL(*public_key);
	CleanupStack::PushL(rsa_verifier);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_verifyL(), before VerifyL().\n")));

	TBool result = rsa_verifier->VerifyL(p_hash, *rsa_signature);
	eap_status_e status;
	if (result)
	{
		// Verify successful
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("eap_am_crypto_symbian: RSA verify successful.\n")));	
		status = eap_status_ok;
	}
	else
	{
		// Verify failed
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("eap_am_crypto_symbian: RSA verify failed.\n")));
		status = eap_status_illegal_parameter; 
	}

	CleanupStack::PopAndDestroy(rsa_verifier);	
	CleanupStack::PopAndDestroy(rsa_signature);	
	CleanupStack::PopAndDestroy(public_key);	
	CleanupStack::PopAndDestroy(arrayPtr);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::rsa_verifyL(), OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}
//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::rsa_cleanup(
	eap_variable_data_c * const /*rsa_context*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::dsa_init(
	eap_variable_data_c * const dsa_context)
{	
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	eap_status_e status = dsa_context->init(0);
	if (status != eap_status_ok)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	dsa_context->set_is_valid(); 

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}

//--------------------------------------------------
EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::dsa_sign(
	eap_variable_data_c * const dsa_context,
	const eap_variable_data_c * const private_dsa_key,
	const eap_variable_data_c * const hash,
	eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_sign(), begins.\n")));

	eap_status_e status = eap_status_ok;

	TRAPD(err, dsa_signL(
		dsa_context,
		private_dsa_key,
		hash,
		signed_hash));
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_sign() failed, err %d, status %d.\n"),
			err,
			status));
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_crypto_symbian_c::dsa_signL(
	eap_variable_data_c * const dsa_context,
	const eap_variable_data_c * const private_dsa_key,
	const eap_variable_data_c * const hash,
	eap_variable_data_c * const signed_hash)
{
	EAP_UNREFERENCED_PARAMETER(dsa_context);
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), begins.\n")));

	TPtrC8 ptr(
		private_dsa_key->get_data(private_dsa_key->get_data_length()), 
		private_dsa_key->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, private_dsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	// The private_dsa_key is ASN.1 encoded and contains DSA parameters and public and private keys.
	// It must be decoded before it can be used.
	// SEQUENCE {
	//	  INTEGER version
	//	  INTEGER p
	//	  INTEGER q
	//	  INTEGER g
	//	  INTEGER Y
	//	  INTEGER X
	// }
	//
	//
	TASN1DecSequence seq;
	TASN1DecInteger asn1;
	TASN1DecGeneric* gen;
	RInteger param_p;
	RInteger param_q;
	RInteger param_g;	
	RInteger public_key;
	RInteger private_key;
	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	TInt pos(0);
	arrayPtr = seq.DecodeDERLC(ptr, pos);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 p = gen->Encoding();			
	if (p.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	param_p = asn1.DecodeDERLongL(p, pos);
	CleanupStack::PushL(param_p);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(2);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 q = gen->Encoding();
	if (q.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	param_q = asn1.DecodeDERLongL(q, pos);
	CleanupStack::PushL(param_q);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(3);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 g = gen->Encoding();
	if (g.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	param_g = asn1.DecodeDERLongL(g, pos);
	CleanupStack::PushL(param_g);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(4);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 Y = gen->Encoding();
	if (Y.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	pos = 0;
	public_key = asn1.DecodeDERLongL(Y, pos);
	CleanupStack::PushL(public_key);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(5);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 X = gen->Encoding();
	if (X.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	pos = 0;
	private_key = asn1.DecodeDERLongL(X, pos);
	CleanupStack::PushL(private_key);		

	CDSAPrivateKey* priv_key = CDSAPrivateKey::NewL(param_p, param_q, param_g, private_key);
	CleanupStack::PushL(priv_key);

	CDSASigner* signer = CDSASigner::NewL(*priv_key);
	CleanupStack::PushL(signer);

	TPtrC8 data(
		hash->get_data(hash->get_data_length()), 
		hash->get_data_length());
	if (data.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, hash is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	
	const CDSASignature* signature = signer->SignL(data);

	RInteger R = RInteger::NewL(signature->R());
	CleanupStack::PushL(R);
	RInteger S = RInteger::NewL(signature->S());
	CleanupStack::PushL(S);
	
	CASN1EncSequence* sequence = CASN1EncSequence::NewLC();
	CASN1EncBigInt* enc_r = CASN1EncBigInt::NewLC(R);
	CASN1EncBigInt* enc_s = CASN1EncBigInt::NewLC(S);

	sequence->AddChildL(enc_r);
	
	sequence->AddChildL(enc_s);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), before NewLC().\n")));

	HBufC8* buf = HBufC8::NewLC(sequence->LengthDER());
	TPtr8 tmp = buf->Des();
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), before WriteDERL().\n")));

	tmp.SetLength(sequence->LengthDER());
	pos = 0;
	sequence->WriteDERL(tmp, (TUint&) pos);
	
	eap_status_e status = signed_hash->set_copy_of_buffer(tmp.Ptr(), tmp.Length());
	if (status != eap_status_ok)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_signL() failed, signed_hash is invalid, status %d.\n"),
			status));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrNoMemory);
	}

	CleanupStack::PopAndDestroy(buf);
	CleanupStack::Pop(enc_s);		// BigInts are deleted by the sequence
	CleanupStack::Pop(enc_r);		// BigInts are deleted by the sequence

	CleanupStack::PopAndDestroy(sequence);
	CleanupStack::PopAndDestroy(&S);
	CleanupStack::PopAndDestroy(&R);
	CleanupStack::PopAndDestroy(signer);
	CleanupStack::PopAndDestroy(priv_key);
	CleanupStack::PopAndDestroy(&private_key);
	CleanupStack::PopAndDestroy(&public_key);
	CleanupStack::PopAndDestroy(&param_g);
	CleanupStack::PopAndDestroy(&param_q);
	CleanupStack::PopAndDestroy(&param_p);
	CleanupStack::PopAndDestroy(arrayPtr);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_signL(), OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::dsa_verify(
	eap_variable_data_c * const dsa_context,		
	const eap_variable_data_c * const public_dsa_key,
	const eap_variable_data_c * const dsa_param_p,
	const eap_variable_data_c * const dsa_param_q,
	const eap_variable_data_c * const dsa_param_g,
	const eap_variable_data_c * const hash,
	const eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verify(), begins.\n")));

	eap_status_e status = eap_status_ok;

	__UHEAP_MARK;
	TRAPD(err, dsa_verifyL(
		dsa_context,
		public_dsa_key,
		dsa_param_p,
		dsa_param_q,
		dsa_param_g,
		hash,
		signed_hash));
	__UHEAP_MARKEND;
	if (err != KErrNone)
	{
		status = ((m_am_tools)->convert_am_error_to_eapol_error(err));
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verify() failed, err %d, status %d.\n"),
			err,
			status));
	} 
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

void eap_am_crypto_symbian_c::dsa_verifyL(
	eap_variable_data_c * const /*dsa_context*/,		
	const eap_variable_data_c * const public_dsa_key,
	const eap_variable_data_c * const dsa_param_p,
	const eap_variable_data_c * const dsa_param_q,
	const eap_variable_data_c * const dsa_param_g,
	const eap_variable_data_c * const hash,
	const eap_variable_data_c * const signed_hash)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(1), begins.\n")));

	// Parameters
	TPtrC8 p(
		dsa_param_p->get_data(dsa_param_p->get_data_length()), 
		dsa_param_p->get_data_length());
	if (p.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(2) failed, dsa_param_p is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	TPtrC8 q(
		dsa_param_q->get_data(dsa_param_q->get_data_length()), 
		dsa_param_q->get_data_length());
	if (q.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(3) failed, dsa_param_q is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}
	TPtrC8 g(
		dsa_param_g->get_data(dsa_param_g->get_data_length()), 
		dsa_param_g->get_data_length());
	if (g.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(4) failed, dsa_param_g is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	

	RInteger P = RInteger::NewL(p);
	CleanupStack::PushL(P);
	
	RInteger Q = RInteger::NewL(q);
	CleanupStack::PushL(Q);
	
	RInteger G = RInteger::NewL(g);
	CleanupStack::PushL(G);

	TPtrC8 calculated_hash(
		hash->get_data(hash->get_data_length()), 
		hash->get_data_length());
	if (calculated_hash.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(5) failed, hash is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	
	// Public key is ASN.1 encoded so it must be decoded
	TPtrC8 pkey (
		public_dsa_key->get_data(public_dsa_key->get_data_length()), 
		public_dsa_key->get_data_length());
	if (pkey.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(6) failed, public_dsa_key is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TASN1DecInteger asn1;
	TInt pos(0);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(7), before DecodeDERLongL().\n")));

	RInteger public_key_int = asn1.DecodeDERLongL(
		pkey, 
		pos);	
	
	CleanupStack::PushL(public_key_int);	
	CDSAPublicKey* pub_key = CDSAPublicKey::NewL(P, Q, G, public_key_int);
	// RIntegers needs to be popped because CDSAPublicKey frees them
	CleanupStack::Pop(&public_key_int);
	CleanupStack::Pop(&G);
	CleanupStack::Pop(&Q);
	CleanupStack::Pop(&P);
	CleanupStack::PushL(pub_key);

	TPtrC8 ptr(
		signed_hash->get_data(hash->get_data_length()),
		signed_hash->get_data_length());
	if (ptr.Ptr() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(8) failed, signed_hash is invalid.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}		

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(9), before DecodeDERLC().\n")));

	TASN1DecSequence seq;	
	TASN1DecGeneric* gen;
	RInteger R;
	RInteger S;
	CArrayPtrFlat<TASN1DecGeneric>* arrayPtr;
	pos = 0;
	arrayPtr = seq.DecodeDERLC(ptr, pos);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(10), before DecodeDERLongL().\n")));

	gen = arrayPtr->At(0);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}

	TPtrC8 r = gen->Encoding();
	if (r.Length() == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	
	pos = 0;
	R = asn1.DecodeDERLongL(r, pos);
	CleanupStack::PushL(R);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(11), before arrayPtr->At(1).\n")));

	gen = arrayPtr->At(1);
	if (gen == 0)
	{
		EAP_TRACE_DEBUG(
			m_am_tools,
			TRACE_FLAGS_ERROR,
			(EAPL("eap_am_crypto_symbian_c::dsa_verifyL() failed, illegal data.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		User::Leave(KErrArgument);
	}	

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(12), before gen->Encoding().\n")));

	TPtrC8 s = gen->Encoding();
	pos = 0;

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(13), before DecodeDERLongL().\n")));

	S = asn1.DecodeDERLongL(s, pos);
	CleanupStack::PushL(S);
	
	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(14), before CDSASignature::NewL().\n")));

	CDSASignature* signature = CDSASignature::NewL(R, S);
	// Parameters needs to be popped because CDSASignature frees them
	CleanupStack::Pop(&S);
	CleanupStack::Pop(&R);
	CleanupStack::PushL(signature);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(15), before CDSAVerifier::NewL().\n")));

	CDSAVerifier* verifier = CDSAVerifier::NewL(*pub_key);
	CleanupStack::PushL(verifier);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(16), before VerifyL().\n")));

	TBool result = verifier->VerifyL(calculated_hash, *signature);
	if (result == EFalse)
	{
		// Verify failed
		EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_ERROR, (EAPL("eap_am_crypto_symbian: DSA verify failed.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_ERROR);
		User::Leave(KErrArgument);
	}

	EAP_TRACE_DEBUG(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("eap_am_crypto_symbian: DSA verify successful.\n")));

	CleanupStack::PopAndDestroy(verifier);
	CleanupStack::PopAndDestroy(signature);
	CleanupStack::PopAndDestroy(arrayPtr);
	CleanupStack::PopAndDestroy(pub_key);

	EAP_TRACE_DEBUG(
		m_am_tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("eap_am_crypto_symbian_c::dsa_verifyL(17), OK.\n")));

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);	
}


//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::dsa_cleanup(
	eap_variable_data_c * const /*dsa_context*/)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_md5_digest_length(
	eap_variable_data_c * const md5_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(md5_context->get_is_valid());
	
	CMessageDigest *ctx = (CMessageDigest *)md5_context->get_data(md5_context->get_data_length());
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return ctx->HashSize();	
}

//--------------------------------------------------


EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_md5_block_size(
	eap_variable_data_c * const /* md5_context */)
{
	return MD5_BLOCK_SIZE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md5_init(
	eap_variable_data_c * const md5_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	CMessageDigest *md5 = 0;

	TRAPD(ret, md5 = CMD5::NewL());
	
	if (ret != KErrNone)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	if (md5_context->get_is_valid_data() == true)
	{
		md5_cleanup(md5_context);
	}

	eap_status_e status = md5_context->set_buffer(md5, sizeof(*md5), false, false);
	if (status != eap_status_ok)
	{
		delete md5;
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md5_update(
	eap_variable_data_c * const md5_context,
	const u8_t * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	
	EAP_ASSERT(md5_context != 0);
	EAP_ASSERT(md5_context->get_is_valid() == true);
	if (md5_context == 0
		|| md5_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	CMessageDigest *md5 = (CMessageDigest *)md5_context->get_data(sizeof(CMessageDigest));
	
	if (md5 == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	// This breaks the const type.
	TPtr8 tmp(const_cast<u8_t *>(data), data_length, data_length);

	md5->Hash(tmp);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md5_final(
	eap_variable_data_c * const md5_context,
	u8_t * const message_digest,
	u32_t *md_length_or_null)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(md5_context != 0);
	EAP_ASSERT(md5_context->get_is_valid() == true);
	if (md5_context == 0
		|| md5_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	CMessageDigest *md5 = (CMessageDigest *)md5_context->get_data(sizeof(CMessageDigest));

	if (md5 == 0
		|| message_digest == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (md_length_or_null != 0)
	{
		*md_length_or_null = md5->HashSize();
	}

	TPtrC8 digest = md5->Hash(TPtrC8(0,0));

	if (digest.Ptr() == 0)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	m_am_tools->memmove(message_digest, digest.Ptr(), md5->HashSize());

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md5_cleanup(
	eap_variable_data_c * const md5_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(md5_context != 0);
	EAP_ASSERT(md5_context->get_is_valid() == true);
	if (md5_context == 0
		|| md5_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	
	CMessageDigest *md5 = (CMessageDigest *)md5_context->get_data(sizeof(CMessageDigest));

	delete md5;

	md5_context->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md5_copy_context(
	eap_variable_data_c * const copied_md5_context,
	const eap_variable_data_c * const original_md5_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	CMessageDigest *ctx_copy = 0;

	if (original_md5_context == 0
		|| original_md5_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	CMessageDigest *ctx = (CMessageDigest *)original_md5_context->get_data(sizeof(CMessageDigest));

	TRAPD(ret, ctx_copy = ctx->CopyL());

	if (ret != KErrNone)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = copied_md5_context->set_buffer(ctx_copy, sizeof(*ctx_copy), false, false);
	if (status != eap_status_ok)
	{
		delete ctx_copy;		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_md4_digest_length(
	eap_variable_data_c * const md4_context)
{
	if (md4_context == 0
		|| md4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_md4_c * const md4 = reinterpret_cast<eap_am_crypto_md4_c *>(
		md4_context->get_data(sizeof(eap_am_crypto_md4_c)));

	if (md4 == 0
		|| md4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	return md4->get_digest_length();
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::get_md4_block_size(
	eap_variable_data_c * const md4_context)
{
	if (md4_context == 0
		|| md4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_md4_c * const md4 = reinterpret_cast<eap_am_crypto_md4_c *>(
		md4_context->get_data(sizeof(eap_am_crypto_md4_c)));

	if (md4 == 0
		|| md4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}

	return md4->get_block_size();
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md4_init(
	eap_variable_data_c * const md4_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	if (md4_context == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	if (md4_context->get_is_valid_data() == true)
	{
		md4_cleanup(md4_context);
	}

	eap_am_crypto_md4_c * const md4 = new eap_am_crypto_md4_c(m_am_tools);
	if (md4 == 0
		|| md4->get_is_valid() == false)
	{
		delete md4;
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	eap_status_e status = md4->hash_init();
	if (status != eap_status_ok)
	{
		delete md4;
		return EAP_STATUS_RETURN(m_am_tools, status);
	}

	if (md4_context->get_is_valid_data() == true)
	{
		md4_cleanup(md4_context);
	}

	status = md4_context->set_buffer(md4, sizeof(*md4), false, true);
	if (status != eap_status_ok)
	{
		delete md4;		
	}

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md4_update(
	eap_variable_data_c * const md4_context,
	const u8_t * const data,
	const u32_t data_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(md4_context != 0);
	EAP_ASSERT(md4_context->get_is_valid() == true);
	if (md4_context == 0
		|| md4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_md4_c * const md4 = reinterpret_cast<eap_am_crypto_md4_c *>(
		md4_context->get_data(sizeof(eap_am_crypto_md4_c)));

	if (md4 == 0
		|| md4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status =  md4->hash_update(
		data,
		data_length);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md4_final(
	eap_variable_data_c * const md4_context,
	u8_t * const message_digest,
	u32_t * md_length_or_null)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(md4_context != 0);
	EAP_ASSERT(md4_context->get_is_valid() == true);
	if (md4_context == 0
		|| md4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_md4_c * const md4 = reinterpret_cast<eap_am_crypto_md4_c *>(
		md4_context->get_data(sizeof(eap_am_crypto_md4_c)));

	if (md4 == 0
		|| md4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status =  md4->hash_final(
		message_digest,
		md_length_or_null);

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md4_cleanup(
	eap_variable_data_c * const md4_context)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_ASSERT(md4_context != 0);
	EAP_ASSERT(md4_context->get_is_valid() == true);
	if (md4_context == 0
		|| md4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	eap_am_crypto_md4_c * const md4 = reinterpret_cast<eap_am_crypto_md4_c *>(
		md4_context->get_data(sizeof(eap_am_crypto_md4_c)));
	
	delete md4;

	md4_context->reset();

	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, eap_status_ok);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::md4_copy_context(
	eap_variable_data_c * const copied_md4_context,
	const eap_variable_data_c * const original_md4_context)
{
	if (original_md4_context == 0
		|| original_md4_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_md4_c * const md4 = reinterpret_cast<eap_am_crypto_md4_c *>(
		original_md4_context->get_data(sizeof(eap_am_crypto_md4_c)));

	if (md4 == 0
		|| md4->get_is_valid() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_am_crypto_md4_c * const md4_copy = md4->copy();
	if (md4_copy == 0
		|| md4_copy->get_is_valid() == false)
	{
		delete md4_copy;
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	eap_status_e status = copied_md4_context->set_buffer(md4_copy, sizeof(*md4_copy), false, true);
	if (status != eap_status_ok)
	{
		delete md4_copy;
	}
	
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::aes_set_encryption_key(
	eap_variable_data_c * const aes_context,
	const u8_t * const key, const u32_t key_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);

	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("encryption_key"),
		key, key_length));

	if (key_length != aes_key_length())
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	TPtrC8 aes_key(key, key_length);
	
	CAESEncryptor* aes = 0;
	TRAPD(err, aes = CAESEncryptor::NewL(aes_key));
	if (err != KErrNone)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Probably weak crypto library installed. FATAL.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// If context is already reserved then cleanup it.
	if (aes_context->get_is_valid_data() == true)
	{
		aes_cleanup(aes_context);
	}

	eap_status_e status = aes_context->set_buffer( 
		aes,
		sizeof(*aes),
		false,
		false);
	if (status != eap_status_ok)
	{
		delete aes;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);

}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::aes_set_decryption_key(
	eap_variable_data_c * const aes_context,
	const u8_t * const key, const u32_t key_length)
{
	EAP_TRACE_BEGIN(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("decryption_key"),
		key, key_length));

	if (key_length != aes_key_length())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	TPtrC8 aes_key(key, key_length);
	
	CAESDecryptor* aes = 0;
	TRAPD(err, aes = CAESDecryptor::NewL(aes_key));
	if (err != KErrNone)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Probably weak crypto library installed. FATAL.\n")));
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// If context is already reserved then cleanup it.
	if (aes_context->get_is_valid_data() == true)
	{
		aes_cleanup(aes_context);
	}

	eap_status_e status = aes_context->set_buffer( 
		aes,
		sizeof(*aes),
		false,
		false);
	if (status != eap_status_ok)
	{
		delete aes;		
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);

}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::aes_cleanup(
	eap_variable_data_c * const aes_context)
{
	EAP_ASSERT(aes_context != 0);
	EAP_ASSERT(aes_context->get_is_valid() == true);
	if (aes_context == 0
		|| aes_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	CRijndael* aes = reinterpret_cast<CRijndael *>(aes_context->get_data(sizeof(CRijndael)));
	
	delete aes;	
	
	aes_context->reset();

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::aes_encrypt_block(
	eap_variable_data_c * const aes_context,
	const u8_t * const data_in,
	u8_t * const data_out,
	const u32_t data_length)
{
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("AES data_in"),
		data_in, data_length));

	if (data_length != aes_block_size())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_encryption_failure);
	}

	EAP_ASSERT(aes_context != 0);
	EAP_ASSERT(aes_context->get_is_valid() == true);
	if (aes_context == 0
		|| aes_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	CAESEncryptor* aes = (CAESEncryptor*)aes_context->get_data(sizeof(CAESEncryptor)); 
	if (aes == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	Mem::Copy(data_out, data_in, data_length);
	
	TPtr8 ptr(data_out, data_length, data_length);
	
	aes->Transform(ptr);
	
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("AES data_out"),
		data_out, data_length));

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::aes_decrypt_block(
	eap_variable_data_c * const aes_context,
	const u8_t * const data_in,
	u8_t * const data_out,
	const u32_t data_length)
{
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("AES data_in"),
		data_in, data_length));

	if (data_length != aes_block_size())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_decryption_failure);
	}

	EAP_ASSERT(aes_context != 0);
	EAP_ASSERT(aes_context->get_is_valid() == true);
	if (aes_context == 0
		|| aes_context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	CAESDecryptor* aes = (CAESDecryptor*)aes_context->get_data(sizeof(CAESDecryptor)); 
	if (aes == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	// Copy input to output so we can transform it in the output buffer
	Mem::Copy(data_out, data_in, data_length);
	
	TPtr8 ptr(data_out, data_length, data_length);
	
	aes->Transform(ptr);
	
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("AES data_out"),
		data_out, data_length));

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::key_length_3des_ede()
{
	return 3ul * BLOCK_SIZE_3DES_EDE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT u32_t eap_am_crypto_symbian_c::block_size_3des_ede()
{
	return BLOCK_SIZE_3DES_EDE;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::set_encryption_key_3des_ede(
	eap_variable_data_c * const context,
	const u8_t * const key, const u32_t key_length)
{
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("encryption_key"),
		key, key_length));

	if (key_length != key_length_3des_ede())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	TPtrC8 des_key(key, key_length);
	
	C3DESEncryptor* ede_3des = 0;
	TRAPD(err, ede_3des = C3DESEncryptor::NewL(des_key));
	if (err != KErrNone)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Probably weak crypto library installed. FATAL.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// If context is already reserved then cleanup it.
	if (context->get_is_valid_data() == true)
	{
		cleanup_3des_ede(context);
	}

	eap_status_e status = context->set_buffer( 
		ede_3des,
		sizeof(*ede_3des),
		false,
		false);
	if (status != eap_status_ok)
	{
		delete ede_3des;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::cleanup_3des_ede(
	eap_variable_data_c * const context)
{
	EAP_ASSERT(context != 0);
	EAP_ASSERT(context->get_is_valid() == true);
	if (context == 0
		|| context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	C3DES* ede_3des = (C3DES*)context->get_data(sizeof(C3DES));
	
	delete ede_3des;

	context->reset();

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::set_decryption_key_3des_ede(
	eap_variable_data_c * const context,
	const u8_t * const key, const u32_t key_length)
{
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("decryption_key"),
		key, key_length));

	if (key_length != key_length_3des_ede())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_key_error);
	}
	
	TPtrC8 des_key(key, key_length);
	
	C3DESDecryptor* ede_3des = 0;
	TRAPD(err, ede_3des = C3DESDecryptor::NewL(des_key));
	if (err != KErrNone)
	{
		EAP_TRACE_ERROR(m_am_tools, TRACE_FLAGS_DEFAULT, (EAPL("Probably weak crypto library installed. FATAL.\n")));
		return EAP_STATUS_RETURN(m_am_tools, eap_status_allocation_error);
	}

	// If context is already reserved then cleanup it.
	if (context->get_is_valid_data() == true)
	{
		cleanup_3des_ede(context);
	}

	eap_status_e status = context->set_buffer( // 
		ede_3des,
		sizeof(*ede_3des),
		false,
		false);
	if (status != eap_status_ok)
	{
		delete ede_3des;
	}
	EAP_TRACE_END(m_am_tools, TRACE_FLAGS_DEFAULT);
	return EAP_STATUS_RETURN(m_am_tools, status);
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::encrypt_block_3des_ede(
	eap_variable_data_c * const context,
	const u8_t * const data_in,
	u8_t * const data_out,
	const u32_t data_length)
{
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("3DES-EDE encrypt data_in"),
		data_in, data_length));

	if (data_length != block_size_3des_ede())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_encryption_failure);
	}
	
	EAP_ASSERT(context != 0);
	EAP_ASSERT(context->get_is_valid() == true);
	if (context == 0
		|| context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	C3DESEncryptor* ede_3des = (C3DESEncryptor*)context->get_data(sizeof(C3DESEncryptor)); 
	if (ede_3des == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	Mem::Copy(data_out, data_in, data_length);
	
	TPtr8 ptr(data_out, data_length, data_length);
	
	ede_3des->Transform(ptr);
	
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("3DES-EDE encrypt data_out"),
		data_out, data_length));

	return eap_status_ok;
}

//--------------------------------------------------

EAP_FUNC_EXPORT eap_status_e eap_am_crypto_symbian_c::decrypt_block_3des_ede(
	eap_variable_data_c * const context,
	const u8_t * const data_in,
	u8_t * const data_out,
	const u32_t data_length)
{
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("3DES-EDE decrypt data_in"),
		data_in, data_length));

	if (data_length != block_size_3des_ede())
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_decryption_failure);
	}
	
	EAP_ASSERT(context != 0);
	EAP_ASSERT(context->get_is_valid() == true);
	if (context == 0
		|| context->get_is_valid_data() == false)
	{
		EAP_TRACE_END(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO);
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}

	C3DESDecryptor* ede_3des = (C3DESDecryptor*)context->get_data(sizeof(C3DESDecryptor)); 
	if (ede_3des == 0)
	{
		return EAP_STATUS_RETURN(m_am_tools, eap_status_illegal_parameter);
	}
	
	Mem::Copy(data_out, data_in, data_length);
	
	TPtr8 ptr(data_out, data_length, data_length);
	
	ede_3des->Transform(ptr);
	
	EAP_TRACE_DATA_DEBUG(m_am_tools, TRACE_FLAGS_EAP_AM_CRYPTO, (EAPL("3DES-EDE decrypt data_out"),
		data_out, data_length));

	return eap_status_ok;
}

//--------------------------------------------------




// End.
