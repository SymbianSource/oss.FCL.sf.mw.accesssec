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
* Description:  Expanded EAP-type on Symbian.
*
*/

/*
* %version: 16 %
*/

#include <EapExpandedType.h>
#include "EapTraceSymbian.h"
#include "eap_expanded_type.h"

//--------------------------------------------------

#if defined(USE_EAP_EXPANDED_TYPE_TRACES)

	#define EXPANDED_TYPE_EAP_TRACE EAP_TRACE_DEBUG_SYMBIAN

	#define EXPANDED_TYPE_EAP_TRACE_DATA EAP_TRACE_DATA_DEBUG_SYMBIAN

	#define EXPANDED_TYPE_EAP_TRACE_RETURN_STRING EAP_TRACE_RETURN_STRING_SYMBIAN

#else

	#define EXPANDED_TYPE_EAP_TRACE(_parameter_list_)

	#define EXPANDED_TYPE_EAP_TRACE_DATA(_parameter_list_)

	#define EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_parameter_list_)

#endif //#if defined(USE_EAP_EXPANDED_TYPE_TRACES)

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType::TEapExpandedType()
{
	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::TEapExpandedType(): EapExpandedTypeNone"),
		&EapExpandedTypeNone,
		sizeof(EapExpandedTypeNone)));

	EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_L("returns: TEapExpandedType::TEapExpandedType()\n"));

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::TEapExpandedType(): EapExpandedTypeNone.GetType()"),
		EapExpandedTypeNone.GetType(),
		sizeof(*(EapExpandedTypeNone.GetType()))));

	iValue.Copy(*(EapExpandedTypeNone.GetType()));

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::TEapExpandedType()"),
		iValue.Ptr(),
		iValue.Length()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType::~TEapExpandedType()
{
	EAP_STATIC_ASSERT(sizeof(TConstEapExpandedTypeTemplate<KEapExpandedTypeLength>) == sizeof(TBufC8<KEapExpandedTypeLength>));
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType::TEapExpandedType(const TEapExpandedType * const init)
{
	EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_L("returns: TEapExpandedType::TEapExpandedType(const TEapExpandedType * const init)\n"));

	iValue.Copy(init->GetValue());

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::TEapExpandedType()"),
		iValue.Ptr(),
		iValue.Length()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType::TEapExpandedType(const TEapExpandedType & init)
{
	EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_L("returns: TEapExpandedType::TEapExpandedType(const TEapExpandedType & init)\n"));

	iValue.Copy(init.GetValue());

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::TEapExpandedType()"),
		iValue.Ptr(),
		iValue.Length()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType::TEapExpandedType(const TBufC8<KEapExpandedTypeLength> & init)
{
	EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_L("returns: TEapExpandedType::TEapExpandedType(const TBufC8<KEapExpandedTypeLength> & init)\n"));

	iValue.Copy(init);

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::TEapExpandedType()"),
		iValue.Ptr(),
		iValue.Length()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType::TEapExpandedType(const TDesC8 & init)
{
	EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_L("returns: TEapExpandedType::TEapExpandedType(const TDesC8 & init)\n"));

	iValue.Copy(init);

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::TEapExpandedType()"),
		iValue.Ptr(),
		iValue.Length()));
}

//--------------------------------------------------

EAP_FUNC_EXPORT const TBuf8<KEapExpandedTypeLength> & TEapExpandedType::GetValue() const
{
	return iValue;
}

//--------------------------------------------------

EAP_FUNC_EXPORT TInt TEapExpandedType::SetValue(
	const void * const data,
	const TUint data_length)
{
	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::SetValue(const void * const data, const TUint data_length)"),
		data,
		data_length));

	EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_L("returns: TEapExpandedType::SetValue()\n"));

	if (data == 0
		|| data_length > iValue.MaxSize())
	{
		return KErrArgument;
	}

	iValue.Copy(reinterpret_cast<const TUint8 *> (data), static_cast<TInt>(data_length));

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::SetValue(const void * const data, const TUint data_length)"),
		iValue.Ptr(),
		iValue.Length()));

	return KErrNone;
}

//--------------------------------------------------

EAP_FUNC_EXPORT TInt TEapExpandedType::SetValue(
	const TUint vendor_id,
	const TUint vendor_type)
{
	const u32_t expanded_vendor = (0xfe000000 | static_cast<u32_t>(vendor_id));
	const TUint net_ord_vendor = eap_htonl(expanded_vendor);
	const TUint net_ord_type = eap_htonl(vendor_type);

	EXPANDED_TYPE_EAP_TRACE((_L("TEapExpandedType::SetValue(): vendor_id=0x%08x, vendor_type=0x%08x, expanded_vendor=0x%08x, net_ord_vendor=0x%08x, net_ord_type=0x%08x\n"),
		vendor_id,
		vendor_type,
		expanded_vendor,
		net_ord_vendor,
		net_ord_type));

	EXPANDED_TYPE_EAP_TRACE_RETURN_STRING(_L("returns: TEapExpandedType::SetValue()\n"));

	if ((sizeof(vendor_id)+sizeof(vendor_type)) > iValue.MaxSize())
	{
		return KErrArgument;
	}

	iValue.Copy(reinterpret_cast<const TUint8 *>(&net_ord_vendor), sizeof(net_ord_vendor));
	iValue.Append(reinterpret_cast<const TUint8 *>(&net_ord_type), sizeof(net_ord_type));

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::SetValue()"),
		iValue.Ptr(),
		iValue.Length()));

	return KErrNone;
}

//--------------------------------------------------

EAP_FUNC_EXPORT TUint TEapExpandedType::GetVendorId() const
{
	const TUint * const aHostOrderVendorId = reinterpret_cast<const TUint *>(iValue.Ptr());

	// Masks off the leading octet 0xfe.
	const u32_t VENDOR_ID_MASK = 0x00ffffff;
	return eap_ntohl(*aHostOrderVendorId) & VENDOR_ID_MASK;
}

//--------------------------------------------------

EAP_FUNC_EXPORT TUint TEapExpandedType::GetVendorType() const
{
	const TUint * const aHostOrderVendorType = reinterpret_cast<const TUint *>(iValue.Ptr() + sizeof(TUint));

	return eap_ntohl(*aHostOrderVendorType);
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType &TEapExpandedType::operator = (const TEapExpandedType &right_type_value)
{
	if (this == &right_type_value)
	{
		return *this;
	}

	iValue.Copy(right_type_value.GetValue());

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::operator ="),
		iValue.Ptr(),
		iValue.Length()));

	return *this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType &TEapExpandedType::operator = (const TBufC8<KEapExpandedTypeLength> &right_type_value)
{
	iValue.Copy(right_type_value);

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::operator ="),
		iValue.Ptr(),
		iValue.Length()));

	return *this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT TEapExpandedType &TEapExpandedType::operator = (const TDesC8 &right_type_value)
{
	ASSERT(right_type_value.Length() == KEapExpandedTypeLength);

	iValue.Copy(right_type_value);

	EXPANDED_TYPE_EAP_TRACE_DATA(
		(EAPL("TEapExpandedType::operator ="),
		iValue.Ptr(),
		iValue.Length()));

	return *this;
}

//--------------------------------------------------

EAP_FUNC_EXPORT TInt TEapExpandedType::Compare(const TEapExpandedType &right_type_value) const
{
	for (TUint ind = 0ul; ind < KEapExpandedTypeLength; ++ind)
	{
		const TUint8 left = iValue[ind];
		const TUint8 right = right_type_value.GetValue()[ind];

		if (left != right)
		{
			return iValue[ind] - right_type_value.GetValue()[ind];
		}
	}

	return 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool TEapExpandedType::operator == (const TEapExpandedType &right_type_value) const
{
	return Compare(right_type_value) == 0;
}

//--------------------------------------------------

EAP_FUNC_EXPORT bool TEapExpandedType::operator != (const TEapExpandedType &right_type_value) const
{
	return Compare(right_type_value) != 0;
}

//--------------------------------------------------
// End of file
