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
* Description:  Conversion functions between common code and Symbian code.
*
*/

/*
* %version: 50 %
*/

// This is enumeration of EAPOL source code.
#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)
	#undef EAP_FILE_NUMBER_ENUM
	#define EAP_FILE_NUMBER_ENUM 738 
	#undef EAP_FILE_NUMBER_DATE 
	#define EAP_FILE_NUMBER_DATE 1127594498 
#endif //#if defined(USE_EAP_MINIMUM_RELEASE_TRACES)


// INCLUDE FILES

#include "EapConversion.h"
#include "eap_am_assert.h"
#include <EapTypeInfo.h>
#include "abs_eap_am_tools.h"
#include "eap_automatic_variable.h"
#include <utf.h>                           // for CnvUtfConverter
#include "abs_eap_plugin_message.h"
#include "eap_plugin_message_base.h"
#include "abs_eap_am_message_if.h"
#include "eap_am_message_if.h"
#include "eap_automatic_variable.h"
#include "eap_plugin_client_message_if.h"
#include "eap_am_message_if_symbian.h"
#include "EapTraceSymbian.h"

// LOCAL CONSTANTS


// ================= MEMBER FUNCTIONS =======================

EAP_FUNC_EXPORT TInt CEapConversion::ConvertFromTDesCToInternal(
	abs_eap_am_tools_c * const tools,
	const TDesC & input16,
	eap_variable_data_c * const target8)
{
	HBufC16* buf16 = HBufC16::New(input16.Length());
	if (buf16 == 0)
	{
		return KErrNoMemory;
	}

	buf16->Des().Copy(input16);

	TPtr16 inBufPtr16 = buf16->Des();

	TInt error = ConvertFromBuf16ToInternal(
		tools,
		&inBufPtr16,
		target8);

	delete buf16;

	return error;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertCipherSuitesToInternalType(
	abs_eap_am_tools_c * const tools,
	const RArray<TUint> * const aCipherSuites,
	eap_array_c<u16_t> * const internal_cipher_suites)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertCipherSuitesToInternalType()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertCipherSuitesToInternalType()");

	eap_status_e status(eap_status_ok);

	if (aCipherSuites == 0
		|| internal_cipher_suites == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	for (TInt ind = 0; ind < aCipherSuites->Count(); ind++)
	{
		u16_t * const tmp_object = new u16_t;
		if (tmp_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}
		*tmp_object = static_cast<u16_t>((*aCipherSuites)[ind]);
		status = internal_cipher_suites->add_object(tmp_object, true);
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertInternalTypeToCipherSuites(
	abs_eap_am_tools_c * const tools,
	const eap_array_c<u16_t> * const internal_cipher_suites,
	RArray<TUint> * const aCipherSuites)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertInternalTypeToCipherSuites()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertInternalTypeToCipherSuites()");

	if (aCipherSuites == 0
		|| internal_cipher_suites == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	for (TInt ind = 0; ind < internal_cipher_suites->get_object_count(); ind++)
	{
		const u16_t * const tmp_object = internal_cipher_suites->get_object(ind);
		if (tmp_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}

		TInt error = aCipherSuites->Append(static_cast<TUint>(*tmp_object));
		if (error != KErrNone)
		{
			return (error);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertFromInternalToBuf16(
	abs_eap_am_tools_c * const tools,
	const eap_variable_data_c * const input8,
	TDes * const target16)
{
	EAP_TRACE_DATA_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertFromInternalToBuf16(): input8"),
        input8->get_data(),
		input8->get_data_length()));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertFromInternalToBuf16()");

	TPtrC8 inBufPtrC8(input8->get_data(), input8->get_data_length());

	// convert utf8 -> unicode,
	// aInBuf8 is UTF8 string, unicode max length is
	// then the length of UTF8 string.
	// NOTE, HBufC16 length means count of 16-bit objects.
	HBufC16 * outBuf16 = HBufC16::New(inBufPtrC8.Size());
	if (outBuf16 == 0)
	{
		EAP_UNREFERENCED_PARAMETER(tools);
		return KErrNoMemory;
	}

	TPtr16 outBufPtr16 = outBuf16->Des();

	CnvUtfConverter::ConvertToUnicodeFromUtf8(outBufPtr16, inBufPtrC8);

	target16->Copy(outBufPtr16);

    EAP_TRACE_DATA_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertFromInternalToBuf16(): outBufPtr16"),
	    outBufPtr16.Ptr(),
		outBufPtr16.Size()));

    delete outBuf16;
    outBuf16 = NULL;

    return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertFromBuf16ToInternal(
	abs_eap_am_tools_c * const tools,
	const TDes * const input16,
	eap_variable_data_c * const target8)
{
	EAP_TRACE_DATA_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertFromBuf16ToInternal(): input16"),
        input16->Ptr(),
		input16->Size()));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertFromBuf16ToInternal()");

	if (tools == 0)
	{
		return KErrArgument;
	}

    // "In UTF-8, characters are encoded using sequences of 1 to 6 octets."
    // RFC2279 - UTF-8
    const TUint KMaxNumberOfOctetsPerUtf8Char = 6;
	// Convert unicode -> utf8.
	// Note, HBufC16 length means the number of 16-bit values or
    // data items represented by the descriptor.
    // Multiply number of charachters by max number of octets for char.
	HBufC8 * aOutBuf8 = HBufC8::New(input16->Length() * KMaxNumberOfOctetsPerUtf8Char);
	if (aOutBuf8 == 0)
	{
		return KErrNoMemory;
	}

	TPtr8 outBufPtr8(aOutBuf8->Des());

	CnvUtfConverter::ConvertFromUnicodeToUtf8(outBufPtr8, *input16);

	eap_status_e status = target8->set_copy_of_buffer(aOutBuf8->Ptr(), aOutBuf8->Length());
	
    delete aOutBuf8;
    aOutBuf8 = NULL;
    
    EAP_TRACE_DATA_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertFromBuf16ToInternal(): target8"),
	    target8->get_data(),
		target8->get_data_length()));

	return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, status)));
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertEAPTypesToInternalTypes(
	abs_eap_am_tools_c * const tools,
	const RArray<TUint> * const EncapsulatedEAPTypes,
	eap_array_c<eap_type_value_e> * const target)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertEAPTypesToInternalTypes()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertEAPTypesToInternalTypes()");

	eap_status_e status(eap_status_ok);

        if (tools == 0)
        {
                return KErrGeneral;
        }
        if (EncapsulatedEAPTypes == 0
		|| target == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	for (TInt ind = 0; ind < EncapsulatedEAPTypes->Count(); ind++)
	{
		eap_type_value_e * const tmp_object = new eap_type_value_e(
			static_cast<eap_type_ietf_values_e>((*EncapsulatedEAPTypes)[ind]));
		if (tmp_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}
		status = target->add_object(tmp_object, true);
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertInternalTypesToEAPTypes(
	abs_eap_am_tools_c * const tools,
	const eap_array_c<eap_type_value_e> * const internal_eap_types,
	RArray<TUint> * const target)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertInternalTypesToEAPTypes()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertInternalTypesToEAPTypes()");

	if (internal_eap_types == 0
		|| target == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	for (TInt ind = 0; ind < internal_eap_types->get_object_count(); ind++)
	{
		const eap_type_value_e * const tmp_object = internal_eap_types->get_object(ind);
		if (tmp_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}

		TInt error = target->Append(static_cast<TUint>(tmp_object->get_vendor_type()));
		if (error != KErrNone)
		{
			return (error);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertExpandedEAPTypeToInternalType(
	const TEapExpandedType * const EncapsulatedExpandedEAPType,
	eap_type_value_e * const target)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapConversion::ConvertExpandedEAPTypeToInternalType()\n")));

	EAP_TRACE_RETURN_STRING_SYMBIAN((_L("returns: CEapConversion::ConvertExpandedEAPTypeToInternalType()\n")));

	eap_status_e status = target->set_expanded_type_data(
		0, // NOTE, we do not have abs_eap_am_tools_c object here.
		EncapsulatedExpandedEAPType->GetValue().Ptr(),
		EncapsulatedExpandedEAPType->GetValue().Length());
	if (status != eap_status_ok)
	{
		return KErrGeneral;
	}

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertInternalTypeToExpandedEAPType(
	const eap_type_value_e * const source,
	TEapExpandedType * const EncapsulatedExpandedEAPType)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("CEapConversion::ConvertInternalTypeToExpandedEAPType()\n")));

	EAP_TRACE_RETURN_STRING_SYMBIAN((_L("returns: CEapConversion::ConvertInternalTypeToExpandedEAPType()\n")));

	TInt error = EncapsulatedExpandedEAPType->SetValue(
		source->get_vendor_id(),
		source->get_vendor_type());

	return error;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertExpandedEAPTypesToInternalTypes(
	abs_eap_am_tools_c * const tools,
	const RArray<TEapExpandedType> * const EncapsulatedExpandedEAPTypes,
	eap_array_c<eap_type_value_e> * const target)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertExpandedEAPTypesToInternalTypes()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertExpandedEAPTypesToInternalTypes()");

	eap_status_e status(eap_status_ok);

	if (EncapsulatedExpandedEAPTypes == 0
		|| target == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	for (TInt ind = 0; ind < EncapsulatedExpandedEAPTypes->Count(); ind++)
	{
		TEapExpandedType ExpandedEAPType = (*EncapsulatedExpandedEAPTypes)[ind];

		eap_type_value_e * const new_object = new eap_type_value_e();
		if (new_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}

		TInt error = ConvertExpandedEAPTypeToInternalType(
			&ExpandedEAPType,
			new_object);
		if (error != KErrNone)
		{
			delete new_object;
			(void) EAP_STATUS_RETURN(tools, tools->convert_am_error_to_eapol_error(error));
			return error;
		}

		status = target->add_object(new_object, true);
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertInternalTypesToExpandedEAPTypes(
	abs_eap_am_tools_c * const tools,
	const eap_array_c<eap_type_value_e> * const source,
	RArray<TEapExpandedType> * const EncapsulatedExpandedEAPTypes)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertInternalTypesToExpandedEAPTypes()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertInternalTypesToExpandedEAPTypes()");

	if (source == 0
		|| EncapsulatedExpandedEAPTypes == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	TEapExpandedType EapType;

	for (TInt ind = 0; ind < source->get_object_count(); ind++)
	{
		const eap_type_value_e * const tmp_object = source->get_object(ind);
		if (tmp_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}

		TInt error = ConvertInternalTypeToExpandedEAPType(
			tmp_object,
			&EapType);
		if (error != KErrNone)
		{
			(void) EAP_STATUS_RETURN(tools, tools->convert_am_error_to_eapol_error(error));
			return (error);
		}

		error = EncapsulatedExpandedEAPTypes->Append(EapType);
		if (error != KErrNone)
		{
			(void) EAP_STATUS_RETURN(tools, tools->convert_am_error_to_eapol_error(error));
			return (error);
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertInternalTypesToHBufC8(
	abs_eap_am_tools_c * const tools,
	const eap_array_c<eap_type_value_e> * const source,
	HBufC8 ** const EncapsulatedExpandedEAPTypesData)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertInternalTypesToHBufC8(): EncapsulatedExpandedEAPTypesData=0x%08x, source=0x%08x\n"),
		EncapsulatedExpandedEAPTypesData,
		source));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertInternalTypesToHBufC8()");

	if (EncapsulatedExpandedEAPTypesData == 0
		|| source == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	*EncapsulatedExpandedEAPTypesData = HBufC8::New(source->get_object_count()*KEapExpandedTypeLength);

	eap_automatic_variable_c<HBufC8> automatic_EncapsulatedExpandedEAPTypesData(
		tools,
		*EncapsulatedExpandedEAPTypesData);

	TPtr8 aDbBinaryColumnValuePtr = (*EncapsulatedExpandedEAPTypesData)->Des();			

	TEapExpandedType EapType;

	for (u32_t ind = 0; ind < source->get_object_count(); ind++)
	{
		const eap_type_value_e * const tmp_object = source->get_object(ind);
		if (tmp_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}

		TInt error = ConvertInternalTypeToExpandedEAPType(
			tmp_object,
			&EapType);
		if (error != KErrNone)
		{
			(void) EAP_STATUS_RETURN(tools, tools->convert_am_error_to_eapol_error(error));
			return (error);
		}

		aDbBinaryColumnValuePtr.Append(EapType.GetValue());
	}


	automatic_EncapsulatedExpandedEAPTypesData.do_not_free_variable();

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertHBufC8ToInternalTypes(
	abs_eap_am_tools_c * const tools,
	const HBufC8 * const EncapsulatedExpandedEAPTypesData,
	eap_array_c<eap_type_value_e> * const target)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertHBufC8ToInternalTypes(): EncapsulatedExpandedEAPTypesData=0x%08x, target=0x%08x\n"),
		EncapsulatedExpandedEAPTypesData,
		target));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertHBufC8ToInternalTypes()");

	if (EncapsulatedExpandedEAPTypesData == 0
		|| target == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	u32_t eap_type_count = EncapsulatedExpandedEAPTypesData->Length() / KEapExpandedTypeLength;

	target->reset();

	const TUint8 * const data = EncapsulatedExpandedEAPTypesData->Ptr();
	u32_t offset = 0ul;

	for (u32_t ind = 0; ind < eap_type_count; ind++)
	{
		eap_type_value_e * const new_object = new eap_type_value_e();

		eap_automatic_variable_c<eap_type_value_e> automatic_new_object(
			tools,
			new_object);

		if (new_object == 0)
		{
			EAP_TRACE_END(tools, TRACE_FLAGS_DEFAULT);
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}

		eap_status_e status = new_object->set_expanded_type_data(
			tools,
			&(data[offset]),
			KEapExpandedTypeLength);
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}

		offset += KEapExpandedTypeLength;

		automatic_new_object.do_not_free_variable();

		status = target->add_object(new_object, true);
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}
	}

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertCertificatesToInternalType(
	abs_eap_am_tools_c * const tools,
	const RPointerArray<EapCertificateEntry> * const aCertificates,
	eap_array_c<eap_certificate_entry_c> * const internal_certificates)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertCertificatesToInternalType()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertCertificatesToInternalType()");

	eap_status_e status(eap_status_ok);

	if (aCertificates == 0
		|| internal_certificates == 0)
	{
		EAP_STATIC_ASSERT(eap_certificate_entry_c::eap_certificate_type_CA == static_cast<eap_certificate_entry_c::eap_certificate_type_e>(EapCertificateEntry::ECA));
		EAP_STATIC_ASSERT(eap_certificate_entry_c::eap_certificate_type_user == static_cast<eap_certificate_entry_c::eap_certificate_type_e>(EapCertificateEntry::EUser));
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  	for( TInt count=0; count < aCertificates->Count(); count++ )
  	{
		const EapCertificateEntry * const cert = (*aCertificates)[count];
		if (cert == 0)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
		}

		eap_certificate_entry_c * const int_entry = new eap_certificate_entry_c(tools);

		eap_automatic_variable_c<eap_certificate_entry_c> automatic_certificate_entry(
			tools,
			int_entry);

		if (int_entry == 0)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetCertType() != EapCertificateEntry::EUser
			&& cert->GetCertType() != EapCertificateEntry::ECA)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
		}

		int_entry->m_CertType = static_cast<eap_certificate_entry_c::eap_certificate_type_e>(cert->GetCertType());

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetSubjectNamePresent())
		{
			ConvertFromBuf16ToInternal(tools, cert->GetSubjectName(), &(int_entry->m_SubjectName));

			int_entry->m_SubjectNamePresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetIssuerNamePresent())
		{
			ConvertFromBuf16ToInternal(tools, cert->GetIssuerName(), &(int_entry->m_IssuerName));

			int_entry->m_IssuerNamePresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetSerialNumberPresent())
		{
			ConvertFromBuf16ToInternal(tools, cert->GetSerialNumber(), &(int_entry->m_SerialNumber));

			int_entry->m_SerialNumberPresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetSubjectKeyIdPresent())
		{
			status = int_entry->m_SubjectKeyID.set_copy_of_buffer(cert->GetSubjectKeyId().Ptr(), cert->GetSubjectKeyId().Length());
			if (status != eap_status_ok)
			{
				return (tools->convert_eapol_error_to_am_error(
					EAP_STATUS_RETURN(tools, status)));
			}

			int_entry->m_SubjectKeyIDPresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetThumbprintPresent())
		{
			ConvertFromBuf16ToInternal(tools, cert->GetThumbprint(), &(int_entry->m_Thumbprint));

			int_entry->m_ThumbprintPresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetLabelPresent())
		{
			ConvertFromBuf16ToInternal(tools, cert->GetLabel(), &(int_entry->m_Label));

			int_entry->m_LabelPresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetPrimaryNamePresent())
		{
			ConvertFromBuf16ToInternal(tools, cert->GetPrimaryName(), &(int_entry->m_PrimaryName));

			int_entry->m_PrimaryNamePresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetSecondaryNamePresent())
		{
			ConvertFromBuf16ToInternal(tools, cert->GetSecondaryName(), &(int_entry->m_SecondaryName));

			int_entry->m_SecondaryNamePresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		if (cert->GetIsEnabledPresent())
		{
			if (cert->GetIsEnabled())
			{
				int_entry->m_iIsEnabled = true;
			}
			else
			{
				int_entry->m_iIsEnabled = false;
			}

			int_entry->m_iIsEnabledPresent = true;
		}

		// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

		automatic_certificate_entry.do_not_free_variable();

		status = internal_certificates->add_object(int_entry, true);
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertInternalTypeToCertificates(
	abs_eap_am_tools_c * const tools,
	const eap_certificate_entry_c::eap_certificate_type_e select_certificate_type,
	const eap_array_c<eap_certificate_entry_c> * const internal_certificates,
	RPointerArray<EapCertificateEntry> * const aCertificates)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertInternalTypeToCertificates()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertInternalTypeToCertificates()");

	if (aCertificates == 0
		|| internal_certificates == 0)
	{
		EAP_STATIC_ASSERT(eap_certificate_entry_c::eap_certificate_type_CA == static_cast<eap_certificate_entry_c::eap_certificate_type_e>(EapCertificateEntry::ECA));
		EAP_STATIC_ASSERT(eap_certificate_entry_c::eap_certificate_type_user == static_cast<eap_certificate_entry_c::eap_certificate_type_e>(EapCertificateEntry::EUser));
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

  	for( u32_t count=0; count < internal_certificates->get_object_count(); count++ )
  	{
		const eap_certificate_entry_c * const int_entry = internal_certificates->get_object(count);
		if (int_entry == 0)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
		}

		if (int_entry->m_CertType == select_certificate_type)
		{
			EapCertificateEntry * cert = new EapCertificateEntry;

			eap_automatic_variable_c<EapCertificateEntry> automatic_cert(
				tools,
				cert);

			if (cert == 0)
			{
				return (tools->convert_eapol_error_to_am_error(
					EAP_STATUS_RETURN(tools, eap_status_allocation_error)));
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			cert->SetCertType(static_cast<EapCertificateEntry::TCertType>(int_entry->m_CertType));

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_SubjectNamePresent == true)
			{
				ConvertFromInternalToBuf16(tools, &(int_entry->m_SubjectName), cert->GetSubjectNameWritable());

				cert->SetSubjectNamePresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_IssuerNamePresent == true)
			{
				ConvertFromInternalToBuf16(tools, &(int_entry->m_IssuerName), cert->GetIssuerNameWritable());

				cert->SetIssuerNamePresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_SerialNumberPresent == true)
			{
				ConvertFromInternalToBuf16(tools, &(int_entry->m_SerialNumber), cert->GetSerialNumberWritable());

				cert->SetSerialNumberPresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_SubjectKeyIDPresent == true)
			{
				cert->GetSubjectKeyIdWritable()->Copy(int_entry->m_SubjectKeyID.get_data(), int_entry->m_SubjectKeyID.get_data_length());

				cert->SetSubjectKeyIdPresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_ThumbprintPresent == true)
			{
				ConvertFromInternalToBuf16(tools, &(int_entry->m_Thumbprint), cert->GetThumbprintWritable());

				cert->SetThumbprintPresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_LabelPresent == true)
			{
				ConvertFromInternalToBuf16(tools, &(int_entry->m_Label), cert->GetLabelWritable());

				cert->SetLabelPresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_PrimaryNamePresent == true)
			{
				ConvertFromInternalToBuf16(tools, &(int_entry->m_PrimaryName), cert->GetPrimaryNameWritable());

				cert->SetPrimaryNamePresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_SecondaryNamePresent == true)
			{
				ConvertFromInternalToBuf16(tools, &(int_entry->m_SecondaryName), cert->GetSecondaryNameWritable());

				cert->SetSecondaryNamePresent();
			}

			// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

			if (int_entry->m_iIsEnabledPresent == true)
			{
				if (int_entry->m_iIsEnabled == true)
				{
					cert->SetIsEnabled(ETrue);
				}

				cert->SetIsEnabledPresent();
			}

			EAP_TRACE_SETTINGS(cert);

			TInt error = aCertificates->Append(cert);
			if (error != KErrNone)
			{
				aCertificates->ResetAndDestroy(); // ResetAndDestroy() function must be called because the objects represented by the array need to be deleted before the array object is destroyed.
				aCertificates->Close(); // The Close() function must be called before RPointerArray object is destroyed.

				(void) EAP_STATUS_RETURN(tools, tools->convert_am_error_to_eapol_error(error));
				return (error);
			}

			automatic_cert.do_not_free_variable();
		}
	} // for()

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertEAPSettingsToInternalType(
	abs_eap_am_tools_c * const tools,
	const EAPSettings * const aSettings,
	eap_method_settings_c * const internal_settings)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertEAPSettingsToInternalType()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertEAPSettingsToInternalType()");

	if (aSettings == 0
		|| internal_settings == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	EAP_TRACE_SETTINGS(aSettings);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iEAPExpandedType != (*EapExpandedTypeNone.GetType()))
	{
		eap_status_e status = internal_settings->m_EAPType.set_expanded_type_data(
			tools,
			aSettings->iEAPExpandedType.GetValue().Ptr(),
			aSettings->iEAPExpandedType.GetValue().Length());
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iUseAutomaticCACertificatePresent)
	{
		internal_settings->m_UseAutomaticCACertificatePresent = true;

		if (aSettings->iUseAutomaticCACertificate)
		{
			internal_settings->m_UseAutomaticCACertificate = true;
		}
		else
		{
			internal_settings->m_UseAutomaticCACertificate = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iUseAutomaticUsernamePresent)
	{
		internal_settings->m_UseAutomaticUsernamePresent = true;

		if (aSettings->iUseAutomaticUsername)
		{
			internal_settings->m_UseAutomaticUsername = true;
		}
		else
		{
			internal_settings->m_UseAutomaticUsername = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iUseAutomaticRealmPresent)
	{
		internal_settings->m_UseAutomaticRealmPresent = true;

		if (aSettings->iUseAutomaticRealm)
		{
			internal_settings->m_UseAutomaticRealm = true;
		}
		else
		{
			internal_settings->m_UseAutomaticRealm = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iUsernamePresent)
	{
		TInt error = ConvertFromBuf16ToInternal(tools, &(aSettings->iUsername), &(internal_settings->m_Username_fix));
		if (error)
		{
			return error;
		}

		internal_settings->m_UsernamePresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iPasswordExistPresent)
	{
		internal_settings->m_PasswordExistPresent = true;

		if (aSettings->iPasswordExist)
		{
			internal_settings->m_PasswordExist = true;
		}
		else
		{
			internal_settings->m_PasswordExist = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iPasswordPresent)
	{
		TInt error = ConvertFromBuf16ToInternal(tools, &(aSettings->iPassword), &(internal_settings->m_Password));
		if (error)
		{
			return error;
		}

		internal_settings->m_PasswordPresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iRealmPresent)
	{
		TInt error = ConvertFromBuf16ToInternal(tools, &(aSettings->iRealm), &(internal_settings->m_Realm));
		if (error)
		{
			return error;
		}

		internal_settings->m_RealmPresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iUsePseudonymsPresent)
	{
		internal_settings->m_UsePseudonymsPresent = true;

		if (aSettings->iUsePseudonyms)
		{
			internal_settings->m_UsePseudonyms = true;
		}
		else
		{
			internal_settings->m_UsePseudonyms = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iVerifyServerRealmPresent)
	{
		internal_settings->m_VerifyServerRealmPresent = true;

		if (aSettings->iVerifyServerRealm)
		{
			internal_settings->m_VerifyServerRealm = true;
		}
		else
		{
			internal_settings->m_VerifyServerRealm = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iRequireClientAuthenticationPresent)
	{
		internal_settings->m_RequireClientAuthenticationPresent = true;

		if (aSettings->iRequireClientAuthentication)
		{
			internal_settings->m_RequireClientAuthentication = true;
		}
		else
		{
			internal_settings->m_RequireClientAuthentication = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iSessionValidityTimePresent)
	{
		internal_settings->m_SessionValidityTimePresent = true;

		internal_settings->m_SessionValidityTime = static_cast<u32_t>(aSettings->iSessionValidityTime);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iCipherSuitesPresent)
	{
		TInt error = ConvertCipherSuitesToInternalType(
			tools,
			&(aSettings->iCipherSuites),
			&(internal_settings->m_CipherSuites));
		if (error)
		{
			return error;
		}

		internal_settings->m_CipherSuitesPresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iPEAPVersionsPresent)
	{
		internal_settings->m_PEAPVersionsPresent = true;

		if (aSettings->iPEAPv0Allowed)
		{
			internal_settings->m_PEAPv0Allowed = true;
		}
		else
		{
			internal_settings->m_PEAPv0Allowed = false;
		}

		if (aSettings->iPEAPv1Allowed)
		{
			internal_settings->m_PEAPv1Allowed = true;
		}
		else
		{
			internal_settings->m_PEAPv1Allowed = false;
		}

		if (aSettings->iPEAPv2Allowed)
		{
			internal_settings->m_PEAPv2Allowed = true;
		}
		else
		{
			internal_settings->m_PEAPv2Allowed = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iCertificatesPresent)
	{
		TInt error = ConvertCertificatesToInternalType(
			tools,
			&(aSettings->iCertificates),
			&(internal_settings->m_Certificates));
		if (error)
		{
			return error;
		}

		internal_settings->m_CertificatesPresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iEnabledEncapsulatedEAPExpandedTypesPresent)
	{
		TInt error = ConvertExpandedEAPTypesToInternalTypes(
			tools,
			&(aSettings->iEnabledEncapsulatedEAPExpandedTypes),
			&(internal_settings->m_EnabledEncapsulatedEAPTypes));
		if (error)
		{
			return error;
		}

		internal_settings->m_EnabledEncapsulatedEAPTypesPresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iDisabledEncapsulatedEAPExpandedTypesPresent)
	{
		TInt error = ConvertExpandedEAPTypesToInternalTypes(
			tools,
			&(aSettings->iDisabledEncapsulatedEAPExpandedTypes),
			&(internal_settings->m_DisabledEncapsulatedEAPTypes));
		if (error)
		{
			return error;
		}

		internal_settings->m_DisabledEncapsulatedEAPTypesPresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iAuthProvModeAllowedPresent)
	{
		internal_settings->m_AuthProvModeAllowedPresent = true;

		if (aSettings->iAuthProvModeAllowed)
		{
			internal_settings->m_AuthProvModeAllowed = true;
		}
		else
		{
			internal_settings->m_AuthProvModeAllowed = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iUnauthProvModeAllowedPresent)
	{
		internal_settings->m_UnauthProvModeAllowedPresent = true;

		if (aSettings->iUnauthProvModeAllowed)
		{
			internal_settings->m_UnauthProvModeAllowed = true;
		}
		else
		{
			internal_settings->m_UnauthProvModeAllowed = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iPACGroupReferencePresent)
	{
		TInt error = ConvertFromBuf16ToInternal(tools, &(aSettings->iPACGroupReference), &(internal_settings->m_PACGroupReference));
		if (error)
		{
			return error;
		}

		internal_settings->m_RealmPresent = true;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iWarnADHPNoPACPresent)
	{
		internal_settings->m_WarnADHPNoPACPresent = true;

		if (aSettings->iWarnADHPNoPAC)
		{
			internal_settings->m_WarnADHPNoPAC = true;
		}
		else
		{
			internal_settings->m_WarnADHPNoPAC = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iWarnADHPNoMatchingPACPresent)
	{
		internal_settings->m_WarnADHPNoMatchingPACPresent = true;

		if (aSettings->iWarnADHPNoMatchingPAC)
		{
			internal_settings->m_WarnADHPNoMatchingPAC = true;
		}
		else
		{
			internal_settings->m_WarnADHPNoMatchingPAC = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iWarnNotDefaultServerPresent)
	{
		internal_settings->m_WarnNotDefaultServerPresent = true;

		if (aSettings->iWarnNotDefaultServer)
		{
			internal_settings->m_WarnNotDefaultServer = true;
		}
		else
		{
			internal_settings->m_WarnNotDefaultServer = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iShowPassWordPromptPresent)
	{
		internal_settings->m_ShowPassWordPromptPresent = true;

		if (aSettings->iShowPassWordPrompt)
		{
			internal_settings->m_ShowPassWordPrompt = true;
		}
		else
		{
			internal_settings->m_ShowPassWordPrompt = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (aSettings->iUseIdentityPrivacyPresent)
	{
		internal_settings->m_UseIdentityPrivacyPresent = true;

		if (aSettings->iUseIdentityPrivacy)
		{
			internal_settings->m_UseIdentityPrivacy = true;
		}
		else
		{
			internal_settings->m_UseIdentityPrivacy = false;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	
	EAP_TRACE_METHOD_SETTINGS(internal_settings);

	return KErrNone;
}

// ----------------------------------------------------------

EAP_FUNC_EXPORT TInt CEapConversion::ConvertInternalTypeToEAPSettings(
	abs_eap_am_tools_c * const tools,
	const eap_method_settings_c * const internal_settings,
	EAPSettings * const aSettings)
{
	EAP_TRACE_DEBUG(
		tools,
		TRACE_FLAGS_DEFAULT,
		(EAPL("CEapConversion::ConvertInternalTypeToEAPSettings()\n")));

	EAP_TRACE_RETURN_STRING(tools, "returns: CEapConversion::ConvertInternalTypeToEAPSettings()");

	if (aSettings == 0
		|| internal_settings == 0)
	{
		return (tools->convert_eapol_error_to_am_error(
			EAP_STATUS_RETURN(tools, eap_status_illegal_parameter)));
	}

	EAP_TRACE_METHOD_SETTINGS(internal_settings);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	{
		eap_variable_data_c eap_data(tools);

		eap_status_e status = internal_settings->m_EAPType.get_expanded_type_data(
			tools,
			&eap_data);
		if (status != eap_status_ok)
		{
			return (tools->convert_eapol_error_to_am_error(
				EAP_STATUS_RETURN(tools, status)));
		}

		TInt error = aSettings->iEAPExpandedType.SetValue(
			eap_data.get_data(),
			eap_data.get_data_length());
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_UseAutomaticCACertificatePresent == true)
	{
		aSettings->iUseAutomaticCACertificatePresent = ETrue;

		if (internal_settings->m_UseAutomaticCACertificate == true)
		{
			aSettings->iUseAutomaticCACertificate = ETrue;
		}
		else
		{
			aSettings->iUseAutomaticCACertificate = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_UseAutomaticUsernamePresent == true)
	{
		aSettings->iUseAutomaticUsernamePresent = ETrue;

		if (internal_settings->m_UseAutomaticUsername == true)
		{
			aSettings->iUseAutomaticUsername = ETrue;
		}
		else
		{
			aSettings->iUseAutomaticUsername = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_UseAutomaticRealmPresent == true)
	{
		aSettings->iUseAutomaticRealmPresent = ETrue;

		if (internal_settings->m_UseAutomaticRealm == true)
		{
			aSettings->iUseAutomaticRealm = ETrue;
		}
		else
		{
			aSettings->iUseAutomaticRealm = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_UsernamePresent == true)
	{
		TInt error = ConvertFromInternalToBuf16(tools, &(internal_settings->m_Username_fix), &(aSettings->iUsername));
		if (error)
		{
			return error;
		}

		aSettings->iUsernamePresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_PasswordExistPresent == true)
	{
		aSettings->iPasswordExistPresent = ETrue;

		if (internal_settings->m_PasswordExist == true)
		{
			aSettings->iPasswordExist = ETrue;
		}
		else
		{
			aSettings->iPasswordExist = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_PasswordPresent == true)
	{
		TInt error = ConvertFromInternalToBuf16(tools, &(internal_settings->m_Password), &(aSettings->iPassword));
		if (error)
		{
			return error;
		}

		aSettings->iPasswordPresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_RealmPresent == true)
	{
		TInt error = ConvertFromInternalToBuf16(tools, &(internal_settings->m_Realm), &(aSettings->iRealm));
		if (error)
		{
			return error;
		}

		aSettings->iRealmPresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_UsePseudonymsPresent == true)
	{
		aSettings->iUsePseudonymsPresent = ETrue;

		if (internal_settings->m_UsePseudonyms == true)
		{
			aSettings->iUsePseudonyms = ETrue;
		}
		else
		{
			aSettings->iUsePseudonyms = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_VerifyServerRealmPresent == true)
	{
		aSettings->iVerifyServerRealmPresent = ETrue;

		if (internal_settings->m_VerifyServerRealm == true)
		{
			aSettings->iVerifyServerRealm = ETrue;
		}
		else
		{
			aSettings->iVerifyServerRealm = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_RequireClientAuthenticationPresent == true)
	{
		aSettings->iRequireClientAuthenticationPresent = ETrue;

		if (internal_settings->m_RequireClientAuthentication == true)
		{
			aSettings->iRequireClientAuthentication = ETrue;
		}
		else
		{
			aSettings->iRequireClientAuthentication = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_SessionValidityTimePresent == true)
	{
		aSettings->iSessionValidityTimePresent = ETrue;

		aSettings->iSessionValidityTime = static_cast<TUint>(internal_settings->m_SessionValidityTime);
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_CipherSuitesPresent == true)
	{
		TInt error = ConvertInternalTypeToCipherSuites(
			tools,
			&(internal_settings->m_CipherSuites),
			&(aSettings->iCipherSuites));
		if (error)
		{
			return error;
		}

		aSettings->iCipherSuitesPresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_PEAPVersionsPresent == true)
	{
		aSettings->iPEAPVersionsPresent = ETrue;

		if (internal_settings->m_PEAPv0Allowed == true)
		{
			aSettings->iPEAPv0Allowed = ETrue;
		}
		else
		{
			aSettings->iPEAPv0Allowed = EFalse;
		}

		if (internal_settings->m_PEAPv1Allowed == true)
		{
			aSettings->iPEAPv1Allowed = ETrue;
		}
		else
		{
			aSettings->iPEAPv1Allowed = EFalse;
		}

		if (internal_settings->m_PEAPv2Allowed == true)
		{
			aSettings->iPEAPv2Allowed = ETrue;
		}
		else
		{
			aSettings->iPEAPv2Allowed = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_CertificatesPresent == true)
	{
		TInt error = KErrNone;
		
		error = ConvertInternalTypeToCertificates(
			tools,
			eap_certificate_entry_c::eap_certificate_type_user,
			&(internal_settings->m_Certificates),
			&(aSettings->iCertificates));

		if (error)
			{
			return error;	
			}
			
		error = ConvertInternalTypeToCertificates(
			tools,
			eap_certificate_entry_c::eap_certificate_type_CA,
			&(internal_settings->m_Certificates),
			&(aSettings->iCertificates));

		if (error)
			{
			return error;	
			}

		aSettings->iCertificatesPresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_EnabledEncapsulatedEAPTypesPresent == true)
	{
		TInt error = ConvertInternalTypesToExpandedEAPTypes(
			tools,
			&(internal_settings->m_EnabledEncapsulatedEAPTypes),
			&(aSettings->iEnabledEncapsulatedEAPExpandedTypes));
		if (error)
		{
			return error;
		}

		aSettings->iEnabledEncapsulatedEAPExpandedTypesPresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_DisabledEncapsulatedEAPTypesPresent == true)
	{
		TInt error = ConvertInternalTypesToExpandedEAPTypes(
			tools,
			&(internal_settings->m_DisabledEncapsulatedEAPTypes),
			&(aSettings->iDisabledEncapsulatedEAPExpandedTypes));
		if (error)
		{
			return error;
		}

		aSettings->iDisabledEncapsulatedEAPExpandedTypesPresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_AuthProvModeAllowedPresent == true)
	{
		aSettings->iAuthProvModeAllowedPresent = ETrue;

		if (internal_settings->m_AuthProvModeAllowed == true)
		{
			aSettings->iAuthProvModeAllowed = ETrue;
		}
		else
		{
			aSettings->iAuthProvModeAllowed = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_UnauthProvModeAllowedPresent == true)
	{
		aSettings->iUnauthProvModeAllowedPresent = ETrue;

		if (internal_settings->m_UnauthProvModeAllowed == true)
		{
			aSettings->iUnauthProvModeAllowed = ETrue;
		}
		else
		{
			aSettings->iUnauthProvModeAllowed = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_PACGroupReferencePresent == true)
	{
		TInt error = ConvertFromInternalToBuf16(tools, &(internal_settings->m_PACGroupReference), &(aSettings->iPACGroupReference));
		if (error)
		{
			return error;
		}

		aSettings->iPACGroupReferencePresent = ETrue;
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_WarnADHPNoPACPresent == true)
	{
		aSettings->iWarnADHPNoPACPresent = ETrue;

		if (internal_settings->m_WarnADHPNoPAC == true)
		{
			aSettings->iWarnADHPNoPAC = ETrue;
		}
		else
		{
			aSettings->iWarnADHPNoPAC = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_WarnADHPNoMatchingPACPresent == true)
	{
		aSettings->iWarnADHPNoMatchingPACPresent = ETrue;

		if (internal_settings->m_WarnADHPNoMatchingPAC == true)
		{
			aSettings->iWarnADHPNoMatchingPAC = ETrue;
		}
		else
		{
			aSettings->iWarnADHPNoMatchingPAC = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_WarnNotDefaultServerPresent == true)
	{
		aSettings->iWarnNotDefaultServerPresent = ETrue;

		if (internal_settings->m_WarnNotDefaultServer == true)
		{
			aSettings->iWarnNotDefaultServer = ETrue;
		}
		else
		{
			aSettings->iWarnNotDefaultServer = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_ShowPassWordPromptPresent == true)
	{
		aSettings->iShowPassWordPromptPresent = ETrue;

		if (internal_settings->m_ShowPassWordPrompt == true)
		{
			aSettings->iShowPassWordPrompt = ETrue;
		}
		else
		{
			aSettings->iShowPassWordPrompt = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	if (internal_settings->m_UseIdentityPrivacyPresent == true)
	{
		aSettings->iUseIdentityPrivacyPresent = ETrue;

		if (internal_settings->m_UseIdentityPrivacy == true)
		{
			aSettings->iUseIdentityPrivacy = ETrue;
		}
		else
		{
			aSettings->iUseIdentityPrivacy = EFalse;
		}
	}

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	EAP_TRACE_SETTINGS(aSettings);

	return KErrNone;
}

// ----------------------------------------------------------
// End of file
