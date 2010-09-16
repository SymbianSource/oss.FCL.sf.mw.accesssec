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

#ifndef _EAP_CONVERSION_H_
#define _EAP_CONVERSION_H_

// INCLUDES
#include <e32base.h>
#include "eap_array.h"
#include "eap_expanded_type.h"
#include "eap_method_settings.h"
#include "EapExpandedType.h"
#include "EapSettings.h"
#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPCONVERSION_H)
	#define EAP_CLASS_VISIBILITY_EAPCONVERSION_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPCONVERSION_H 
	#define EAP_C_FUNC_VISIBILITY_EAPCONVERSION_H 
	#define EAP_FUNC_EXPORT_EAPCONVERSION_H 
	#define EAP_C_FUNC_EXPORT_EAPCONVERSION_H 
#elif defined(EAP_EXPORT_EAPCONVERSION_H)
	#define EAP_CLASS_VISIBILITY_EAPCONVERSION_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPCONVERSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCONVERSION_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPCONVERSION_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPCONVERSION_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPCONVERSION_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPCONVERSION_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPCONVERSION_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPCONVERSION_H 
	#define EAP_C_FUNC_EXPORT_EAPCONVERSION_H 
#endif
// End: added by script change_export_macros.sh.


// FORWARD DECLARATIONS


// CLASS DECLARATION
/**
* Class that implements the conversion functions for EAP type interface.
*/
class EAP_CLASS_VISIBILITY_EAPCONVERSION_H CEapConversion
{

public:

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertFromTDesCToInternal(
		abs_eap_am_tools_c * const tools,
		const TDesC & input16,
		eap_variable_data_c * const target8);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertFromInternalToBuf16(
		abs_eap_am_tools_c * const tools,
		const eap_variable_data_c * const input8,
		TDes * const target16);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertFromBuf16ToInternal(
		abs_eap_am_tools_c * const tools,
		const TDes * const input16,
		eap_variable_data_c * const target8);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertEAPTypesToInternalTypes(
		abs_eap_am_tools_c * const tools,
		const RArray<TUint> * const EncapsulatedEAPTypes,
		eap_array_c<eap_type_value_e> * const target);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertInternalTypesToEAPTypes(
		abs_eap_am_tools_c * const tools,
		const eap_array_c<eap_type_value_e> * const source,
		RArray<TUint> * const EncapsulatedEAPTypes);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertExpandedEAPTypeToInternalType(
		const TEapExpandedType * const EncapsulatedExpandedEAPType,
		eap_type_value_e * const target);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertInternalTypeToExpandedEAPType(
		const eap_type_value_e * const source,
		TEapExpandedType * const EncapsulatedExpandedEAPType);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertExpandedEAPTypesToInternalTypes(
		abs_eap_am_tools_c * const tools,
		const RArray<TEapExpandedType> * const EncapsulatedExpandedEAPTypes,
		eap_array_c<eap_type_value_e> * const target);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertInternalTypesToExpandedEAPTypes(
		abs_eap_am_tools_c * const tools,
		const eap_array_c<eap_type_value_e> * const source,
		RArray<TEapExpandedType> * const EncapsulatedExpandedEAPTypes);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertInternalTypesToHBufC8(
		abs_eap_am_tools_c * const tools,
		const eap_array_c<eap_type_value_e> * const source,
		HBufC8 ** const EncapsulatedExpandedEAPTypesData);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertHBufC8ToInternalTypes(
		abs_eap_am_tools_c * const tools,
		const HBufC8 * const EncapsulatedExpandedEAPTypesData,
		eap_array_c<eap_type_value_e> * const target);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertCipherSuitesToInternalType(
		abs_eap_am_tools_c * const tools,
		const RArray<TUint> * const aCipherSuites,
		eap_array_c<u16_t> * const internal_cipher_suites);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertInternalTypeToCipherSuites(
		abs_eap_am_tools_c * const tools,
		const eap_array_c<u16_t> * const internal_cipher_suites,
		RArray<TUint> * const aCipherSuites);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertCertificatesToInternalType(
		abs_eap_am_tools_c * const tools,
		const RPointerArray<EapCertificateEntry> * const aCertificates,
		eap_array_c<eap_certificate_entry_c> * const internal_certificates);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertInternalTypeToCertificates(
		abs_eap_am_tools_c * const tools,
		const eap_certificate_entry_c::eap_certificate_type_e select_certificate_type,
		const eap_array_c<eap_certificate_entry_c> * const internal_certificates,
		RPointerArray<EapCertificateEntry> * const aCertificates);


	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertEAPSettingsToInternalType(
		abs_eap_am_tools_c * const tools,
		const EAPSettings * const aSettings,
		eap_method_settings_c * const internal_settings);

	EAP_FUNC_VISIBILITY_EAPCONVERSION_H static TInt ConvertInternalTypeToEAPSettings(
		abs_eap_am_tools_c * const tools,
		const eap_method_settings_c * const internal_settings,
		EAPSettings * const aSettings);

};

#endif // _EAP_CONVERSION_H_

// End of file
