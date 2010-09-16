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

#if !defined(_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H_)
#define _ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H_


#include "eap_tools.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H 
#elif defined(EAP_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H)
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H 
	#define EAP_C_FUNC_EXPORT_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H 
#endif
// End: added by script change_export_macros.sh.


//--------------------------------------------------

/// This is interface to bit store of the Bloom filter algorithm.
/** The bit store should be divided to two stores.
 *  New bits are stored to the current bit store.
 *  When current bit store becames over populated it should be
 *  changed previous bit store and a new current bit store should be created.
 *  Each bit index should be checked from current and previous bit stores.
 *  Over population can be calculated from count of set bit and size of the bit store.
 *  When half of the bits are set probability of false filtering will increse
 *  much faster. Probability of false filtering is saturation raised power to bit index count.
 *  Saturation is count of set bits divided by size of bit store.
 *  Bit index count is count of separate indexes extracted from hash digest.
 *  Each index is n bits long. The size of the bit store is 2^n bits.
 */
class EAP_CLASS_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H abs_eap_am_bloom_algorithm_store_c
{

private:

	/**
	 * The set_is_valid() function sets the state of the object valid.
	 * The creator of this object calls this function after it is initialized. 
	 */
	virtual void set_is_valid() = 0;

public:

	/**
	 * The destructor of the abs_eap_am_bloom_algorithm_store_c class does nothing special.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H virtual ~abs_eap_am_bloom_algorithm_store_c()
	{
	}

	/**
	 * The constructor of the abs_eap_am_bloom_algorithm_store_c does nothing special.
	 */
	EAP_FUNC_VISIBILITY_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H abs_eap_am_bloom_algorithm_store_c()
	{
	}

	/**
	 * This function sets the name of the bit store.
	 * Store name is 8-bit string without terminating NULL.
	 */
	virtual eap_status_e set_name_of_store(const eap_variable_data_c * const store_name) = 0;

	/**
	 * This function checks the bit store exists.
	 * Function should return eap_status_ok when bit store exists and is valid.
	 */
	virtual eap_status_e bloom_filter_check_does_bit_store_exists() = 0;

	/**
	 * This is the count of bits in the index of Bloom algorithm.
	 */
	virtual eap_status_e set_bloom_bit_index_size(const u32_t bloom_bit_index_size) = 0;

	/**
	 * This function returns the bit value of queried bit from the current and previous bit store.
	 * @param bit_index indicates the queried bit.
	 */
	virtual u32_t bloom_filter_get_bit_index(const u32_t bit_index) = 0;

	/**
	 * This function sets the bit value of queried bit to the bit store.
	 * @param bit_index indicates the queried bit.
	 */
	virtual eap_status_e bloom_filter_set_bit_index(const u32_t bit_index) = 0;

	/**
	 * Object must indicate it's validity.
	 * If object initialization fails this function must return false.
	 * @return This function returns the validity of this object.
	 */
	virtual bool get_is_valid() = 0;

}; // class eap_am_bloom_algorithm_c

#endif //#if !defined(_ABS_EAP_AM_BLOOM_ALGORITHM_STORE_H_)

//--------------------------------------------------



// End.
