/*
* ============================================================================
*  Name        : ./accesssec/eapol/eapol_framework/wapi_common/include/dummy_wapi_core.h
*  Part of     : WAPI / WAPI       *** Info from the SWAD
*  Description : WAPI authentication
*  Version     : %version: 7 % << Don't touch! Updated by Synergy at check-out.
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
* Template version: 4.2
*/

#ifndef _DUMMY_WAPI_CORE_H_
#define _DUMMY_WAPI_CORE_H_

#include "eap_am_types.h"
#include "abs_eap_base_timer.h"
#include "abs_wapi_am_core.h"
#include "abs_ec_certificate_store.h"


class abs_wapi_am_core_c;
class abs_ec_certificate_store_c;


/**
*  This is a class to create a dummy wapi core object which can be used in the 
*  generation of the platform-specific wapi AM objects in the class that provides 
*  direct access to certificate store 
*/

class dummy_wapi_core_c : public abs_wapi_am_core_c, public abs_ec_certificate_store_c
{

public:

    dummy_wapi_core_c();
    ~dummy_wapi_core_c();
    
    // ---------------------------------------------------------
    // dummy_wapi_core_c::get_is_valid()
    // ---------------------------------------------------------
    //
    bool get_is_valid();
    
    /*******************************************************
     ***********Inhertited from abs_wapi_am_core_c *********
     * *****************************************************/
    
    // ---------------------------------------------------------
    // dummy_wapi_core_c::set_timer()
    // ---------------------------------------------------------
    //
    eap_status_e set_timer(
            abs_eap_base_timer_c * const initializer, 
            const u32_t id, 
            void * const data,
            const u32_t time_ms);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::cancel_timer()
    // ---------------------------------------------------------
    //
    eap_status_e cancel_timer(
            abs_eap_base_timer_c * const initializer, 
            const u32_t id);
    
    // ---------------------------------------------------------
    // dummy_wapi_core_c::set_session_timeout()
    // ---------------------------------------------------------
    //
    eap_status_e set_session_timeout(const u32_t session_timeout_ms);

    /************************************************************
     ********Inhertited from abs_ec_certificate_store_c *********
     ************************************************************/
    
    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_get_own_certificate()
    // ---------------------------------------------------------
    //
    eap_status_e complete_get_own_certificate(
        const eap_variable_data_c * const own_certificate);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_query_asu_id()
    // ---------------------------------------------------------
    //
    eap_status_e complete_query_asu_id(
        const eap_variable_data_c * const asn1_der_subject_name,
        const eap_variable_data_c * const asn1_der_issuer_name,
        const eap_variable_data_c * const asn1_der_sequence_number,
        const eap_status_e id_status);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_select_certificate()
    // ---------------------------------------------------------
    //
    eap_status_e complete_select_certificate(
        const eap_variable_data_c * const issuer_ID,
        const eap_variable_data_c * const certificate_ID,
        const eap_variable_data_c * const certificate);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_read_id_of_certificate()
    // ---------------------------------------------------------
    //
    eap_status_e complete_read_id_of_certificate(
        const eap_variable_data_c * const ID);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_create_signature_with_private_key()
    // ---------------------------------------------------------
    //
    eap_status_e complete_create_signature_with_private_key(
        const eap_variable_data_c * const signature,
        const eap_status_e signature_status);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_verify_signature_with_public_key()
    // ---------------------------------------------------------
    //
    eap_status_e complete_verify_signature_with_public_key(
        const eap_status_e verification_status);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_create_ecdh_temporary_keys()
    // ---------------------------------------------------------
    //
    eap_status_e complete_create_ecdh_temporary_keys(
        const eap_variable_data_c * const private_key_d,
        const eap_variable_data_c * const public_key_x,
        const eap_variable_data_c * const public_key_y);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::complete_create_ecdh()
    // ---------------------------------------------------------
    //
    eap_status_e complete_create_ecdh(
        const eap_variable_data_c * const K_AB_x4,
        const eap_variable_data_c * const K_AB_y4);


    // ---------------------------------------------------------
    // dummy_wapi_core_c::state_notification()
    // ---------------------------------------------------------
    //
    void state_notification( const abs_eap_state_notification_c * const state);

    // ---------------------------------------------------------
    // dummy_wapi_core_c::read_configure()
    // ---------------------------------------------------------
    //
    eap_status_e read_configure(
        const eap_configuration_field_c * const field,
        eap_variable_data_c * const data);
        
private:

	// Nothing

};

#endif

// end of file
