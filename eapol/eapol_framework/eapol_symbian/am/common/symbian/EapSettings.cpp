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
* Description:  Data type for EAP-settings configuration on Symbian.
*
*/

/*
* %version: 44 %
*/

#include <e32debug.h>
#include <EapSettings.h>

#include "EapTraceSymbian.h"
#include "eap_am_export.h"

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT EapCertificateEntry::EapCertificateEntry()
: iCertType(ENone)
, iSubjectNamePresent(EFalse)
, iIssuerNamePresent(EFalse)
, iSerialNumberPresent(EFalse)
, iThumbprintPresent(EFalse)
, iLabelPresent(EFalse)
, iPrimaryNamePresent(EFalse)
, iSecondaryNamePresent(EFalse)
, iIsEnabledPresent(EFalse)
, iSubjectKeyIdPresent(EFalse)
, iIsValid(EFalse)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::EapCertificateEntry(): this=0x%08x"),
		this));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapCertificateEntry::EapCertificateEntry()"));
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT EapCertificateEntry::~EapCertificateEntry()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::~EapCertificateEntry(): this=0x%08x"),
		this));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EapCertificateEntry::~EapCertificateEntry()"));
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::trace() const
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iCertType=%d"),
		iCertType));

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iSubjectNamePresent=%d"),
		iSubjectNamePresent));
	if (iSubjectNamePresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iSubjectName",
			iSubjectName.Ptr(),
			iSubjectName.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iIssuerNamePresent=%d"),
		iIssuerNamePresent));
	if (iIssuerNamePresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iIssuerName",
			iIssuerName.Ptr(),
			iIssuerName.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iSerialNumberPresent=%d"),
		iSerialNumberPresent));
	if (iSerialNumberPresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iSerialNumber",
			iSerialNumber.Ptr(),
			iSerialNumber.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iThumbprintPresent=%d"),
		iThumbprintPresent));
	if (iThumbprintPresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iThumbprint",
			iThumbprint.Ptr(),
			iThumbprint.Size()));
	}


	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iLabelPresent=%d"),
		iLabelPresent));
	if (iLabelPresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iLabel",
			iLabel.Ptr(),
			iLabel.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iPrimaryNamePresent=%d"),
		iPrimaryNamePresent));
	if (iPrimaryNamePresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iPrimaryName",
			iPrimaryName.Ptr(),
			iPrimaryName.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iSecondaryNamePresent=%d"),
		iSecondaryNamePresent));
	if (iSecondaryNamePresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iSecondaryName",
			iSecondaryName.Ptr(),
			iSecondaryName.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iIsEnabledPresent=%d"),
		iIsEnabledPresent));
	if (iIsEnabledPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iIsEnabled=%d"),
			iIsEnabled));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iSubjectKeyIdPresent=%d"),
		iSubjectKeyIdPresent));
	if (iSubjectKeyIdPresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EapCertificateEntry::trace(): iSubjectKeyId",
			iSubjectKeyId.Ptr(),
			iSubjectKeyId.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EapCertificateEntry::trace(): iIsValid=%d"),
		iIsValid));
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT EapCertificateEntry * EapCertificateEntry::Copy()
{
	EapCertificateEntry * const entry = new EapCertificateEntry;
	if (entry == 0)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::Copy(): No memory.\n")));
		return 0;
	}

	*entry = *this;

	if (entry->iIsValid == EFalse)
	{
		delete entry;

		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::Copy(): No memory.\n")));
		return 0;
	}

	return entry;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT EapCertificateEntry &EapCertificateEntry::operator = (const EapCertificateEntry &right_type_value)
{
	if (this == &right_type_value)
	{
		return *this;
	}

	iIsValid = EFalse;


	SetCertType(right_type_value.GetCertType());

	if (right_type_value.GetSubjectNamePresent())
	{
		if (SetSubjectName(*right_type_value.GetSubjectName()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetSubjectName(): No memory.\n")));
			return *this;
		}
	}

	if (right_type_value.GetIssuerNamePresent())
	{
		if (SetIssuerName(*right_type_value.GetIssuerName()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetIssuerName(): No memory.\n")));
			return *this;
		}
	}

	if (right_type_value.GetSerialNumberPresent())
	{
		if (SetSerialNumber(*right_type_value.GetSerialNumber()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetSerialNumber(): No memory.\n")));
			return *this;
		}
	}

	if (right_type_value.GetThumbprintPresent())
	{
		if (SetThumbprint(*right_type_value.GetThumbprint()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetThumbprint(): No memory.\n")));
			return *this;
		}
	}


	if (right_type_value.GetLabelPresent())
	{
		if (SetLabel(*right_type_value.GetLabel()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetLabel(): No memory.\n")));
			return *this;
		}
	}

	if (right_type_value.GetPrimaryNamePresent())
	{
		if (SetPrimaryName(*right_type_value.GetPrimaryName()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetPrimaryName(): No memory.\n")));
			return *this;
		}
	}

	if (right_type_value.GetSecondaryNamePresent())
	{
		if (SetSecondaryName(*right_type_value.GetSecondaryName()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetSecondaryName(): No memory.\n")));
			return *this;
		}
	}

	if (right_type_value.GetIsEnabledPresent())
	{
		if (SetIsEnabled(right_type_value.GetIsEnabled()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetIsEnabled(): No memory.\n")));
			return *this;
		}
	}

	if (right_type_value.GetSubjectKeyIdPresent())
	{
		if (SetSubjectKeyId(right_type_value.GetSubjectKeyId()) != KErrNone)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::operator = (): SetSubjectKeyId(): No memory.\n")));
			return *this;
		}
	}

	iIsValid = ETrue;

	return *this;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetSubjectNamePresent() const
{
	return iSubjectNamePresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetIssuerNamePresent() const
{
	return iIssuerNamePresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetSerialNumberPresent() const
{
	return iSerialNumberPresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetThumbprintPresent() const
{
	return iThumbprintPresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetLabelPresent() const
{
	return iLabelPresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetPrimaryNamePresent() const
{
	return iPrimaryNamePresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetSecondaryNamePresent() const
{
	return iSecondaryNamePresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetIsEnabledPresent() const
{
	return iIsEnabledPresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetSubjectKeyIdPresent() const
{
	return iSubjectKeyIdPresent;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetSubjectNamePresent()
{
	iSubjectNamePresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetIssuerNamePresent()
{
	iIssuerNamePresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetSerialNumberPresent()
{
	iSerialNumberPresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetThumbprintPresent()
{
	iThumbprintPresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetLabelPresent()
{
	iLabelPresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetPrimaryNamePresent()
{
	iPrimaryNamePresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetSecondaryNamePresent()
{
	iSecondaryNamePresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetIsEnabledPresent()
{
	iIsEnabledPresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EapCertificateEntry::SetSubjectKeyIdPresent()
{
	iSubjectKeyIdPresent = ETrue;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT EapCertificateEntry::TCertType EapCertificateEntry::GetCertType() const
{
	return iCertType;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TDes * EapCertificateEntry::GetSubjectName() const
{
	return &iSubjectName;
}
	
//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TDes * EapCertificateEntry::GetIssuerName() const
{
	return &iIssuerName;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TDes * EapCertificateEntry::GetSerialNumber() const
{
	return &iSerialNumber;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TDes * EapCertificateEntry::GetThumbprint() const
{
	return &iThumbprint;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetCertType(const TCertType & aType)
{
	iCertType = aType;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetSubjectName(const TBuf<KGeneralStringMaxLength> & aSubjectName)
{
	iSubjectName.Copy(aSubjectName);
	if (iSubjectName.Length() != aSubjectName.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetSubjectName(): iSubjectName.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iSubjectNamePresent = ETrue;

	return KErrNone;
}
	
//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetIssuerName(const TBuf<KGeneralStringMaxLength> & aIssuerName)
{
	iIssuerName.Copy(aIssuerName);
	if (iIssuerName.Length() != aIssuerName.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetIssuerName(): iIssuerName.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iIssuerNamePresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetSerialNumber(const TBuf<KGeneralStringMaxLength> & aSerialNumber)
{
	iSerialNumber.Copy(aSerialNumber);
	if (iSerialNumber.Length() != aSerialNumber.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetSerialNumber(): iSerialNumber.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iSerialNumberPresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetThumbprint(const TBuf<KThumbprintMaxLength> & aThumbprint)
{
	iThumbprint.Copy(aThumbprint);
	if (iThumbprint.Length() != aThumbprint.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetThumbprint(): iThumbprint.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iThumbprintPresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TDes * EapCertificateEntry::GetLabel() const
{
	return &iLabel;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TKeyIdentifier & EapCertificateEntry::GetSubjectKeyId() const
{
	return iSubjectKeyId;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TDes * EapCertificateEntry::GetPrimaryName() const
{
	return &iPrimaryName;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT const TDes * EapCertificateEntry::GetSecondaryName() const
{
	return &iSecondaryName;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TDes * EapCertificateEntry::GetLabelWritable()
{
	return &iLabel;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TKeyIdentifier * EapCertificateEntry::GetSubjectKeyIdWritable()
{
	return &iSubjectKeyId;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TDes * EapCertificateEntry::GetPrimaryNameWritable()
{
	return &iPrimaryName;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TDes * EapCertificateEntry::GetSecondaryNameWritable()
{
	return &iSecondaryName;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TDes * EapCertificateEntry::GetSubjectNameWritable()
{
	return &iSubjectName;
}
	
//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TDes * EapCertificateEntry::GetIssuerNameWritable()
{
	return &iIssuerName;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TDes * EapCertificateEntry::GetSerialNumberWritable()
{
	return &iSerialNumber;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TDes * EapCertificateEntry::GetThumbprintWritable()
{
	return &iThumbprint;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetIsEnabled() const
{
	return iIsEnabled;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TBool EapCertificateEntry::GetIsValid() const
{
	return iIsValid;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetLabel(const TCertLabel & aLabel)
{
	iLabel.Copy(aLabel);
	if (iLabel.Length() != aLabel.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetLabel(): iLabel.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iLabelPresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetPrimaryName(const TBuf<KMaxCertNameLength> & aPrimaryName)
{
	iPrimaryName.Copy(aPrimaryName);
	if (iPrimaryName.Length() != aPrimaryName.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetPrimaryName(): iPrimaryName.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iPrimaryNamePresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetSecondaryName(const TBuf<KMaxCertNameLength> & aSecondaryName)
{
	iSecondaryName.Copy(aSecondaryName);
	if (iSecondaryName.Length() != aSecondaryName.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetSecondaryName(): iSecondaryName.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iSecondaryNamePresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetSubjectKeyId(const TKeyIdentifier & aSubjectKeyId)
{
	iSubjectKeyId.Copy(aSubjectKeyId);
	if (iSubjectKeyId.Length() != aSubjectKeyId.Length())
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("ERROR: EapCertificateEntry::SetSubjectKeyId(): iSubjectKeyId.Copy(): No memory.\n")));
		return KErrNoMemory;
	}

	iSubjectKeyIdPresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetIsEnabled(const TBool aIsEnabled)
{
	iIsEnabled = aIsEnabled;
	iIsEnabledPresent = ETrue;

	return KErrNone;
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT TInt EapCertificateEntry::SetIsValid(const TBool aIsValid)
{
	iIsValid = aIsValid;

	return KErrNone;
}

//-------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------
//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT EAPSettings::EAPSettings()
: iEAPExpandedType(*(EapExpandedTypeNone.GetType()))
, iUseAutomaticCACertificatePresent(EFalse)
, iUseAutomaticCACertificate(EFalse)
, iUseAutomaticUsernamePresent(EFalse)
, iUseAutomaticUsername(EFalse)
, iUseAutomaticRealmPresent(EFalse)
, iUsernamePresent(EFalse)
, iPasswordExistPresent(EFalse)
, iPasswordExist(EFalse)
, iPasswordPresent(EFalse)
, iRealmPresent(EFalse)
, iUsePseudonymsPresent(EFalse)
, iUsePseudonyms(EFalse)
, iVerifyServerRealmPresent(EFalse)
, iVerifyServerRealm(EFalse)
, iRequireClientAuthenticationPresent(EFalse)
, iRequireClientAuthentication(EFalse)
, iSessionValidityTimePresent(EFalse)
, iSessionValidityTime(0ul)
, iCipherSuitesPresent(EFalse)
, iCipherSuites(1)
, iPEAPVersionsPresent(EFalse)
, iPEAPv0Allowed(EFalse)
, iPEAPv1Allowed(EFalse)
, iPEAPv2Allowed(EFalse)
, iCertificatesPresent(EFalse)
, iCertificates(1)
, iEnabledEncapsulatedEAPExpandedTypesPresent(EFalse)
, iEnabledEncapsulatedEAPExpandedTypes(1)
, iDisabledEncapsulatedEAPExpandedTypesPresent(EFalse)
, iDisabledEncapsulatedEAPExpandedTypes(1)
, iAuthProvModeAllowedPresent(EFalse)
, iAuthProvModeAllowed(EFalse)
, iUnauthProvModeAllowedPresent(EFalse)
, iUnauthProvModeAllowed(EFalse)
, iPACGroupReferencePresent(EFalse)
, iWarnADHPNoPACPresent(EFalse)
, iWarnADHPNoPAC(EFalse)
, iWarnADHPNoMatchingPACPresent(EFalse)
, iWarnADHPNoMatchingPAC(EFalse)
, iWarnNotDefaultServerPresent(EFalse)
, iWarnNotDefaultServer(EFalse)
, iShowPassWordPromptPresent(EFalse)
, iShowPassWordPrompt(EFalse)
, iUseIdentityPrivacyPresent(EFalse)
, iUseIdentityPrivacy(EFalse)
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::EAPSettings(): this=0x%08x"),
		this));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EAPSettings::EAPSettings()"));
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT EAPSettings::~EAPSettings()
{
	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::~EAPSettings(): this=0x%08x"),
		this));
	EAP_TRACE_RETURN_STRING_SYMBIAN(_L("returns: EAPSettings::~EAPSettings()"));

    EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::~EAPSettings(): calls iCipherSuites.Close()")));
	iCipherSuites.Close(); // The Close() function must be called before RArray object is destroyed.

    EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::~EAPSettings(): calls iCertificates.ResetAndDestroy()")));
	iCertificates.ResetAndDestroy(); // ResetAndDestroy() function must be called because the objects represented by the array need to be deleted before the array object is destroyed.
    EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::~EAPSettings(): calls iCertificates.Close()")));
	iCertificates.Close(); // The Close() function must be called before RPointerArray object is destroyed.

    EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::~EAPSettings(): calls iEnabledEncapsulatedEAPExpandedTypes.Close()")));
	iEnabledEncapsulatedEAPExpandedTypes.Close(); // The Close() function must be called before RArray object is destroyed.

    EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::~EAPSettings(): calls iDisabledEncapsulatedEAPExpandedTypes.Close()")));
	iDisabledEncapsulatedEAPExpandedTypes.Close(); // The Close() function must be called before RArray object is destroyed.
}

//-------------------------------------------------------------------------------------

EAP_FUNC_EXPORT void EAPSettings::trace() const
{
	TUint ind = 0ul;

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iEAPExpandedType=0xfe%06x%08x"),
		iEAPExpandedType.GetVendorId(),
		iEAPExpandedType.GetVendorType()));

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iUseAutomaticCACertificatePresent=%d"),
		iUseAutomaticCACertificatePresent));
	if (iUseAutomaticCACertificatePresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iUseAutomaticCACertificate=%d"),
			iUseAutomaticCACertificate) );
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iUseAutomaticUsernamePresent=%d"),
		iUseAutomaticUsernamePresent));
	if (iUseAutomaticUsernamePresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iUseAutomaticUsername=%d"),
			iUseAutomaticUsername) );
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iUseAutomaticRealmPresent=%d"),
		iUseAutomaticRealmPresent));
	if (iUseAutomaticRealmPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iUseAutomaticRealm=%d"),
			iUseAutomaticRealm) );
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iUsernamePresent=%d"),
		iUsernamePresent));
	if (iUsernamePresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EAPSettings::trace():     iUsername",
			iUsername.Ptr(),
			iUsername.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iPasswordExistPresent=%d"),
		iPasswordExistPresent));
	if (iPasswordExistPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iPasswordExist=%d"),
			iPasswordExist) );
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iPasswordPresent=%d"),
		iPasswordPresent));
	if (iPasswordPresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EAPSettings::trace():     iPassword",
			iPassword.Ptr(),
			iPassword.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iRealmPresent=%d"),
		iRealmPresent));
	if (iRealmPresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EAPSettings::trace():     iRealm",
			iRealm.Ptr(),
			iRealm.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iUsePseudonymsPresent=%d"),
		iUsePseudonymsPresent));
	if (iUsePseudonymsPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iUsePseudonyms=%d"),
			iUsePseudonyms) );
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iVerifyServerRealmPresent=%d"),
		iVerifyServerRealmPresent));
	if (iVerifyServerRealmPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iVerifyServerRealm=%d"),
			iVerifyServerRealm));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iRequireClientAuthenticationPresent=%d"),
		iRequireClientAuthenticationPresent));
	if (iRequireClientAuthenticationPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iRequireClientAuthentication=%d"),
			iRequireClientAuthentication));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iSessionValidityTimePresent=%d"),
		iSessionValidityTimePresent));
	if (iSessionValidityTimePresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iSessionValidityTime=%d"),
			iSessionValidityTime));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iCipherSuitesPresent=%d"),
		iCipherSuitesPresent));
	if (iCipherSuitesPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iCipherSuites=%d"),
			iCipherSuites.Count()));
		for (ind = 0ul; ind < iCipherSuites.Count(); ++ind)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iCipherSuites[%d]=%d"),
				ind,
				iCipherSuites[ind]));
		}
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iPEAPVersionsPresent=%d"),
		iPEAPVersionsPresent));
	if (iPEAPVersionsPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iPEAPv0Allowed=%d"),
			iPEAPv0Allowed));
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iPEAPv1Allowed=%d"),
			iPEAPv1Allowed));
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iPEAPv2Allowed=%d"),
			iPEAPv2Allowed));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iCertificatesPresent=%d"),
		iCertificatesPresent));
	if (iCertificatesPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iCertificates=%d"),
			iCertificates.Count()));
		for (ind = 0ul; ind < iCertificates.Count(); ++ind)
		{
			iCertificates[ind]->trace();
		}
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iEnabledEncapsulatedEAPExpandedTypesPresent=%d"),
		iEnabledEncapsulatedEAPExpandedTypesPresent));
	if (iEnabledEncapsulatedEAPExpandedTypesPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iEnabledEncapsulatedEAPExpandedTypes=%d"),
			iEnabledEncapsulatedEAPExpandedTypes.Count()));
		for (ind = 0ul; ind < iEnabledEncapsulatedEAPExpandedTypes.Count(); ++ind)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iEnabledEncapsulatedEAPExpandedTypes[%d]=0xfe%06x%08x"),
				ind,
				iEnabledEncapsulatedEAPExpandedTypes[ind].GetVendorId(),
				iEnabledEncapsulatedEAPExpandedTypes[ind].GetVendorType()));
		}
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iDisabledEncapsulatedEAPExpandedTypesPresent=%d"),
		iDisabledEncapsulatedEAPExpandedTypesPresent));
	if (iDisabledEncapsulatedEAPExpandedTypesPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iDisabledEncapsulatedEAPExpandedTypes=%d"),
			iDisabledEncapsulatedEAPExpandedTypes.Count()));
		for (ind = 0ul; ind < iDisabledEncapsulatedEAPExpandedTypes.Count(); ++ind)
		{
			EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iDisabledEncapsulatedEAPExpandedTypes[%d]=0xfe%06x%08x"),
				ind,
				iDisabledEncapsulatedEAPExpandedTypes[ind].GetVendorId(),
				iDisabledEncapsulatedEAPExpandedTypes[ind].GetVendorType()));
		}
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iAuthProvModeAllowedPresent=%d"),
		iAuthProvModeAllowedPresent));
	if (iAuthProvModeAllowedPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iAuthProvModeAllowed=%d"),
			iAuthProvModeAllowed));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iUnauthProvModeAllowedPresent=%d"),
		iUnauthProvModeAllowedPresent));
	if (iUnauthProvModeAllowedPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iUnauthProvModeAllowed=%d"),
			iUnauthProvModeAllowed));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iPACGroupReferencePresent=%d"),
		iPACGroupReferencePresent));
	if (iPACGroupReferencePresent)
	{
		EAP_TRACE_DATA_DEBUG_SYMBIAN(("EAPSettings::trace():     iPACGroupReference",
			iPACGroupReference.Ptr(),
			iPACGroupReference.Size()));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iWarnADHPNoPACPresent=%d"),
		iWarnADHPNoPACPresent));
	if (iWarnADHPNoPACPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iWarnADHPNoPAC=%d"),
			iWarnADHPNoPAC));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iWarnADHPNoMatchingPACPresent=%d"),
		iWarnADHPNoMatchingPACPresent));
	if (iWarnADHPNoMatchingPACPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iWarnADHPNoMatchingPAC=%d"),
			iWarnADHPNoMatchingPAC));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iWarnNotDefaultServerPresent=%d"),
		iWarnNotDefaultServerPresent));
	if (iWarnNotDefaultServerPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iWarnNotDefaultServer=%d"),
			iWarnNotDefaultServer));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iShowPassWordPromptPresent=%d"),
		iShowPassWordPromptPresent));
	if (iShowPassWordPromptPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iShowPassWordPrompt=%d"),
			iShowPassWordPrompt));
	}

	EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace(): iUseIdentityPrivacyPresent=%d"),
		iUseIdentityPrivacyPresent));
	if (iUseIdentityPrivacyPresent)
	{
		EAP_TRACE_DEBUG_SYMBIAN((_L("EAPSettings::trace():     iUseIdentityPrivacy=%d"),
			iUseIdentityPrivacy));
	}
}

//-------------------------------------------------------------------------------------
// end of file
