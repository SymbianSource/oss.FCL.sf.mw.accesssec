/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/wapi_core/dummy_wapi_core.cpp
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 11 % << Don't touch! Updated by Synergy at check-out.
*
*  Copyright © 2001-2009 Nokia.  All rights reserved.
*  This material, including documentation and any related computer
*  programs, is protected by copyright controlled by Nokia.  All
*  rights are reserved.  Copying, including reproducing, storing,
*  adapting or translating, any or all of this material requires the
*  prior written consent of Nokia.  This material also contains
*  confidential information which may not be disclosed to others
*  without the prior written consent of Nokia.
* ============================================================================
* Template version: 4.1.1
*/

#include "eap_status.h"
#include "eap_am_assert.h"
#include "abs_eap_am_tools.h"
#include "eap_am_types.h"
#include "dummy_wapi_core.h"


// Constructor
dummy_wapi_core_c::dummy_wapi_core_c()
    {
    }
    
// Destructor
dummy_wapi_core_c::~dummy_wapi_core_c()
    {
    }

// Returns the status of the object
bool dummy_wapi_core_c::get_is_valid()
    {
    return true;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/

eap_status_e dummy_wapi_core_c::set_timer(
    abs_eap_base_timer_c * const p_initializer, 
    const u32_t p_id, 
    void * const p_data,
    const u32_t p_time_ms)
    {
    return eap_status_not_found;
    }


/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::cancel_timer( abs_eap_base_timer_c* const initializer, 
                                            const u32_t id)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::set_session_timeout(const u32_t session_timeout_ms)
    {
    return eap_status_not_found;
    }


/************************************************************
 ********Inhertited from abs_ec_certificate_store_c *********
 ************************************************************/

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_get_own_certificate(
    const eap_variable_data_c * const own_certificate)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_query_asu_id(
    const eap_variable_data_c * const asn1_der_subject_name,
    const eap_variable_data_c * const asn1_der_issuer_name,
    const eap_variable_data_c * const asn1_der_sequence_number,
    const eap_status_e id_status)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_select_certificate(
    const eap_variable_data_c * const issuer_ID,
    const eap_variable_data_c * const certificate_ID,
    const eap_variable_data_c * const certificate)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_read_id_of_certificate(
    const eap_variable_data_c * const ID)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_create_signature_with_private_key(
    const eap_variable_data_c * const signature,
    const eap_status_e signature_status)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_verify_signature_with_public_key(
    const eap_status_e verification_status)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_create_ecdh_temporary_keys(
    const eap_variable_data_c * const private_key_d,
    const eap_variable_data_c * const public_key_x,
    const eap_variable_data_c * const public_key_y)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::complete_create_ecdh(
    const eap_variable_data_c * const K_AB_x4,
    const eap_variable_data_c * const K_AB_y4)
    {
    return eap_status_not_found;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
void dummy_wapi_core_c::state_notification( const abs_eap_state_notification_c * const state)
    {
    return;
    }

/********************************************************************
 *  No functionality for inherited function
 ********************************************************************/
eap_status_e dummy_wapi_core_c::read_configure(
    const eap_configuration_field_c * const field,
    eap_variable_data_c * const data)
    {
    return eap_status_not_found;
    }

    
    
