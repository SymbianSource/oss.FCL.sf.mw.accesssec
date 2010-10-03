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

#if !defined(_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H_)
#define _EAPOL_RSNA_KEY_DATA_GTK_HEADER_H_

#include "eapol_header.h"
#include "eap_general_header_base.h"
#include "eapol_key_header.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H 
#elif defined(EAP_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H)
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H 
	#define EAP_C_FUNC_EXPORT_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H 
#endif
// End: added by script change_export_macros.sh.



//------------------------------------------------------

/// This is base class of EAPOL RSNA key data GTK header.
/**
 * @code
 *      0       1       2       3       4       5       6       7
 *  +-------+-------+-------+-------+-------+-------+-------+-------+
 *  |    Key ID     |  Tx   |            Reserved                   |
 *  +-------+-------+-------+-------+-------+-------+-------+-------+
 *  |                      Reserved                                 |
 *  +-------+-------+-------+-------+-------+-------+-------+-------+
 *  |                    GTK (Length -6) Octets                     |
 *  +-                                                             -+
 *  |                                                               |
 *  +-------+-------+-------+-------+-------+-------+-------+-------+
 * @endcode
 */
class EAP_CLASS_VISIBILITY_EAPOL_RSNA_KEY_DATA_GTK_HEADER_H eapol_rsna_key_data_gtk_header_c
: public eap_general_header_base_c
{
private:
	//--------------------------------------------------

	/// This is pointer to the tools class.
	abs_eap_am_tools_c * const m_am_tools;

	//--------------------------------------------------
public:
	//--------------------------------------------------

	enum eapol_rsna_key_data_gtk_header_constants_e
	{
		EAPOL_RSNA_KEY_DATA_FLAGS_FIELD_SIZE          = sizeof(u8_t),
		EAPOL_RSNA_KEY_DATA_RESERVED_FIELD_SIZE       = sizeof(u8_t),
		EAPOL_RSNA_KEY_DATA_INVALID_GTK_INDEX         = 0xff,
	};

	//--------------------------------------------------
protected:
	//--------------------------------------------------

	enum offsets_e
	{
		m_offset_flags                 = 0ul,
		m_offset_reserved              = m_offset_flags                 + EAPOL_RSNA_KEY_DATA_FLAGS_FIELD_SIZE,
		m_offset_gtk                   = m_offset_reserved              + EAPOL_RSNA_KEY_DATA_RESERVED_FIELD_SIZE,
	};

	enum eapol_rsna_key_data_gtk_header_masks_e
	{
		EAPOL_RSNA_KEY_DATA_GTK_INDEX_MASK = 0x03,
		EAPOL_RSNA_KEY_DATA_TX_MASK        = 0x04,
		EAPOL_RSNA_KEY_DATA_RESERVED_MASK  = 0xf8,
	};

	enum eapol_rsna_key_data_gtk_header_shift_e
	{
		EAPOL_RSNA_KEY_DATA_GTK_INDEX_SHIFT = 0x00,
		EAPOL_RSNA_KEY_DATA_TX_SHIFT        = 0x02,
		EAPOL_RSNA_KEY_DATA_RESERVED_SHIFT  = 0x03,
	};

	//--------------------------------------------------
public:
	//--------------------------------------------------

	// 
	virtual ~eapol_rsna_key_data_gtk_header_c();

	// 
	eapol_rsna_key_data_gtk_header_c(
		abs_eap_am_tools_c * const tools,
		void * const header_begin,
		const u32_t header_buffer_length);

	u8_t get_key_index() const;

	bool get_tx_bit() const;

	u8_t * get_gtk_offset(const u32_t offset, const u32_t contignuous_bytes) const;

	/**
	 * This function returns pointer to the GTK.
	 * @param contignuous_bytes is the length of queried data in bytes.
	 */
	u8_t * get_gtk(const u32_t contignuous_bytes) const;

	static u16_t get_header_length();


	eap_status_e set_key_index(const u32_t index);

	eap_status_e set_tx(const bool tx);

	eap_status_e set_reserved_flag(const u32_t reserved);

	eap_status_e set_reserved_field(const u32_t reserved);

	eap_status_e check_header() const;

	eap_status_e reset_header();

	// 
	//--------------------------------------------------
}; // class eapol_rsna_key_data_gtk_header_c


#endif //#if !defined(_EAPOL_RSNA_KEY_DATA_HEADER_H_)

//------------------------------------------------------



// End.
