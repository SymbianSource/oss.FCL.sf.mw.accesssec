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
* Description:  EAP-expanded type definition.
*
*/

/*
* %version: 17 %
*/

#ifndef _SYMBIAN_EAP_EXPANDED_TYPE_H_
#define _SYMBIAN_EAP_EXPANDED_TYPE_H_

#include <e32base.h>

const TUint KEapExpandedTypeLength = 8;

//--------------------------------------------------

class TEapExpandedType
{
public:

	IMPORT_C TEapExpandedType();

	IMPORT_C virtual ~TEapExpandedType();

	IMPORT_C TEapExpandedType(const TEapExpandedType * const init);

	IMPORT_C TEapExpandedType(const TEapExpandedType & init);

	IMPORT_C TEapExpandedType(const TBufC8<KEapExpandedTypeLength> & init);

	IMPORT_C TEapExpandedType(const TDesC8 & init);

	IMPORT_C const TBuf8<KEapExpandedTypeLength> & GetValue() const;

	IMPORT_C TInt SetValue(
		const void * const data,
		const TUint data_length);

	IMPORT_C TInt SetValue(
		const TUint vendor_id,
		const TUint vendor_type);

	IMPORT_C TEapExpandedType &operator = (const TEapExpandedType & right_type_value);

	IMPORT_C TEapExpandedType &operator = (const TBufC8<KEapExpandedTypeLength> & right_type_value);

	IMPORT_C TEapExpandedType &operator = (const TDesC8 &right_type_value);

	IMPORT_C TInt Compare(const TEapExpandedType &right_type_value) const;

	IMPORT_C bool operator == (const TEapExpandedType &right_type_value) const;

	IMPORT_C bool operator != (const TEapExpandedType &right_type_value) const;

	IMPORT_C TUint GetVendorId() const;

	IMPORT_C TUint GetVendorType() const;

private:

	TBuf8<KEapExpandedTypeLength> iValue;
};

//--------------------------------------------------

/// This template is binary compatible with TEapExpandedType.
template <TUint buffer_length>
class TConstEapExpandedTypeTemplate
{
public:

	/// GetType() casts the constant TConstEapExpandedTypeTemplate<KEapExpandedTypeLength> object to TEapExpandedType *.
	inline const TBufC8<buffer_length> * GetType() const;

	// These must be public.
	TUint   m_field_length;
	TUint8  m_field[buffer_length];
};

template <TUint buffer_length>
inline const TBufC8<buffer_length> * TConstEapExpandedTypeTemplate<buffer_length>::GetType() const
{
	return reinterpret_cast<const TBufC8<buffer_length> *>(this);
}

//--------------------------------------------------

/// Macro initializes const TEapExpandedType object named "name".
/// Each value value1 ... value8 initializes 8-bit byte of expanded EAP-type.
/// EAP-type field is defined in RFC3748:
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |               Vendor-Id                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                          Vendor-Type                          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// 
/// Type
/// 
///    254 for Expanded Type
/// 
/// Vendor-Id
/// 
///    The Vendor-Id is 3 octets and represents the SMI Network
///    Management Private Enterprise Code of the Vendor in network byte
///    order, as allocated by IANA.  A Vendor-Id of zero is reserved for
///    use by the IETF in providing an expanded global EAP Type space.
/// 
/// Vendor-Type
/// 
///    The Vendor-Type field is four octets and represents the vendor-
///    specific method Type.
/// 
///    If the Vendor-Id is zero, the Vendor-Type field is an extension
///    and superset of the existing namespace for EAP Types.  The first
///    256 Types are reserved for compatibility with single-octet EAP
///    Types that have already been assigned or may be assigned in the
///    future.  Thus, EAP Types from 0 through 255 are semantically
///    identical, whether they appear as single octet EAP Types or as
///    Vendor-Types when Vendor-Id is zero.  There is one exception to
///    this rule: Expanded Nak and Legacy Nak packets share the same
///    Type, but must be treated differently because they have a
///    different format.
/// 
/// Macro casts initialized TConstEapExpandedTypeTemplate<KEapExpandedTypeLength>.
#define EAP_EXPANDED_TYPE_CONST(name, value1, value2, value3, value4, value5, value6, value7, value8) \
	static const TConstEapExpandedTypeTemplate<KEapExpandedTypeLength> name \
		= {KEapExpandedTypeLength, {value1, value2, value3, value4, value5, value6, value7, value8}}

//--------------------------------------------------

EAP_EXPANDED_TYPE_CONST(EapExpandedTypeNone,           0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);

EAP_EXPANDED_TYPE_CONST(EapExpandedTypeGtc,            0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeTls,            0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0d);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeLeap,           0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeSim,            0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeTtls,           0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeAka,            0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x17);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypePeap,           0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x19);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeMsChapv2,       0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeFast,           0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2b);
EAP_EXPANDED_TYPE_CONST(EapExpandedTypeProtectedSetup, 0xfe, 0x00, 0x37, 0x2a, 0x00, 0x00, 0x00, 0x01);

EAP_EXPANDED_TYPE_CONST(EapExpandedTypeTtlsPap,        0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x62); // This is for internal use only. This value is used in configuration of TTLS/PAP.
EAP_EXPANDED_TYPE_CONST(EapExpandedPlainMsChapv2,      0xfe, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x63); // This is for internal use only. This value is used in configuration of TTLS/plain-MsChapv2.

//--------------------------------------------------

#endif // _SYMBIAN_EAP_EXPANDED_TYPE_H_

// End of file
