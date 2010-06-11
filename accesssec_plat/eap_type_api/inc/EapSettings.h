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
* %version: 11.1.29 %
*/

// Refer the document S60_3_1_EAP_Symbian_Adaptation_Design_C.doc for more 
// details of using EAPSettings. Refer section 9.2 for code samples.

#ifndef EAP_SETTINGS_H
#define EAP_SETTINGS_H

#include <unifiedcertstore.h>
#include <cctcertinfo.h>
#include "EapExpandedType.h"

const TUint KGeneralStringMaxLength = 255;
const TUint KKeyIdentifierLength = 255;
const TUint KThumbprintMaxLength = 64;
/* This is the maximum length of a certificate primary/secondary name we are interested in. */
const TUint32 KMaxCertNameLength = 64;


//-------------------------------------------------------------------------------

class EapCertificateEntry
: public CBase
{

public:

	enum TCertType
	{
		ENone,
		EUser,
		ECA
	};

	IMPORT_C EapCertificateEntry();

	IMPORT_C virtual ~EapCertificateEntry();

	IMPORT_C void trace() const;

	IMPORT_C EapCertificateEntry * Copy();

	// This operator is indentionally without implementation.
	EapCertificateEntry * const operator = (const EapCertificateEntry * const right_type_value); // Do not use this.

	IMPORT_C EapCertificateEntry &operator = (const EapCertificateEntry &right_type_value);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TBool GetSubjectNamePresent() const;

	IMPORT_C TBool GetIssuerNamePresent() const;

	IMPORT_C TBool GetSerialNumberPresent() const;

	IMPORT_C TBool GetThumbprintPresent() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TBool GetLabelPresent() const;

	IMPORT_C TBool GetPrimaryNamePresent() const;

	IMPORT_C TBool GetSecondaryNamePresent() const;

	IMPORT_C TBool GetIsEnabledPresent() const;

	IMPORT_C TBool GetSubjectKeyIdPresent() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C void SetSubjectNamePresent();

	IMPORT_C void SetIssuerNamePresent();

	IMPORT_C void SetSerialNumberPresent();

	IMPORT_C void SetThumbprintPresent();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C void SetLabelPresent();

	IMPORT_C void SetPrimaryNamePresent();

	IMPORT_C void SetSecondaryNamePresent();

	IMPORT_C void SetIsEnabledPresent();

	IMPORT_C void SetSubjectKeyIdPresent();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TCertType GetCertType() const;
	
	IMPORT_C const TDes * GetSubjectName() const;
		
	IMPORT_C const TDes * GetIssuerName() const;
	
	IMPORT_C const TDes * GetSerialNumber() const;
	
	IMPORT_C const TDes * GetThumbprint() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TDes * GetSubjectNameWritable();
		
	IMPORT_C TDes * GetIssuerNameWritable();
	
	IMPORT_C TDes * GetSerialNumberWritable();
	
	IMPORT_C TDes * GetThumbprintWritable();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C const TDes * GetLabel() const;

	IMPORT_C const TKeyIdentifier & GetSubjectKeyId() const;

	IMPORT_C const TDes * GetPrimaryName() const;

	IMPORT_C const TDes * GetSecondaryName() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TDes * GetLabelWritable();

	IMPORT_C TKeyIdentifier * GetSubjectKeyIdWritable();

	IMPORT_C TDes * GetPrimaryNameWritable();

	IMPORT_C TDes * GetSecondaryNameWritable();

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TInt SetCertType(const TCertType & aType);
	
	IMPORT_C TInt SetSubjectName(const TBuf<KGeneralStringMaxLength> & aSubjectName);
		
	IMPORT_C TInt SetIssuerName(const TBuf<KGeneralStringMaxLength> & aIssuerName);
	
	IMPORT_C TInt SetSerialNumber(const TBuf<KGeneralStringMaxLength> & aSerialNumber);
	
	IMPORT_C TInt SetThumbprint(const TBuf<KThumbprintMaxLength> & aThumbprint);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TInt SetLabel(const TCertLabel & aLabel);

	IMPORT_C TInt SetSubjectKeyId(const TKeyIdentifier & aSubjectKeyId);

	IMPORT_C TInt SetPrimaryName(const TBuf<KMaxCertNameLength> & aPrimaryName);

	IMPORT_C TInt SetSecondaryName(const TBuf<KMaxCertNameLength> & aSecondaryName);

	IMPORT_C TInt SetIsEnabled(const TBool aIsEnabled);

	IMPORT_C TInt SetIsValid(const TBool aIsValid);

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	IMPORT_C TBool GetIsEnabled() const;

	IMPORT_C TBool GetIsValid() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - -

private:

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// These members are used by authentication protocols.

	// Specifies whether this entry describes user or CA certificate (mandatory)
	TCertType iCertType;
	
	// Subject name in distinguished name ASCII form. This is optional.
	// For example "/C=US/O=Some organization/CN=Some common name".	
	TBool iSubjectNamePresent;
	TBuf<KGeneralStringMaxLength> iSubjectName;
		
	// Issuer name in distinguished name ASCII form. This is optional.
	// For example "/C=US/O=Some organization/CN=Some common name".
	TBool iIssuerNamePresent;
	TBuf<KGeneralStringMaxLength> iIssuerName;
	
	// Serial number in ASCII form. This is optional.
	TBool iSerialNumberPresent;
	TBuf<KGeneralStringMaxLength> iSerialNumber;
	
	// Thumbprint in binary form. This is optional.
	TBool iThumbprintPresent;
	TBuf<KThumbprintMaxLength> iThumbprint;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// These members are used by UI.

	// This holds only the certificate label. This is the text UI will show.
	TBool iLabelPresent;
	TCertLabel iLabel;

	// Primary name of the certificate if any.
	TBool iPrimaryNamePresent;
	TBuf<KMaxCertNameLength> iPrimaryName;

	// Secondary name of the certificate if any.
	TBool iSecondaryNamePresent;
	TBuf<KMaxCertNameLength> iSecondaryName;

	// UI uses this to indicate enabled certificate.
	TBool iIsEnabledPresent;
	TBool iIsEnabled;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
	// These members are used by both authentication protocols and UI.

	// Subject key in binary form. This is mandatory field to find correct certificate from CUnifiedCertStore. UI uses this too.
	TBool iSubjectKeyIdPresent;
	//TBuf8<KKeyIdentifierLength> iSubjectKeyId;
	TKeyIdentifier iSubjectKeyId; // This is mandatory field to find correct certificate from CUnifiedCertStore.

	// Indicates this object is correctly initialized.
	TBool iIsValid;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
};

//-------------------------------------------------------------------------------

class EAPSettings : public CBase
{
public:	

	IMPORT_C EAPSettings();

	IMPORT_C virtual ~EAPSettings();

	IMPORT_C void trace() const;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Specifies the EAP type these settings are for. 
	// Is not really needed but is here so just some sanity checks can be made
	TEapExpandedType iEAPExpandedType; // Use this in new code.
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Use automatic CA certificate.
	TBool iUseAutomaticCACertificatePresent;
	TBool iUseAutomaticCACertificate;

	// Use automatic username.
	TBool iUseAutomaticUsernamePresent;
	TBool iUseAutomaticUsername;

	// Use automatic realm.
	TBool iUseAutomaticRealmPresent;
	TBool iUseAutomaticRealm;

	// Username in ASCII format
	TBool iUsernamePresent;
	TBuf<KGeneralStringMaxLength> iUsername; 

	/// Get: Whether password is stored in database.
	/// Set: Whether password must be cleared from database.
	TBool iPasswordExistPresent;
	TBool iPasswordExist;

	// Password in ASCII format
	TBool iPasswordPresent;
	TBuf<KGeneralStringMaxLength> iPassword;

	// Realm in ASCII format
	TBool iRealmPresent;
	TBuf<KGeneralStringMaxLength> iRealm; 

	// Use pseudonym identities in EAP-SIM/AKA
	TBool iUsePseudonymsPresent;
	TBool iUsePseudonyms;		

	// Whether EAP-TLS/TTLS/PEAP should verify server realm
	TBool iVerifyServerRealmPresent;
	TBool iVerifyServerRealm;

	// Whether EAP-TLS/TTLS/PEAP should require client authentication
	TBool iRequireClientAuthenticationPresent;
	TBool iRequireClientAuthentication;

	// General session validity time (in minutes)
	TBool iSessionValidityTimePresent;
	TUint iSessionValidityTime;

	// An array of allowed cipher suites for EAP-TLS/TTLS/PEAP. 
	// Refer to RFC2246 chapter A.5 for the values.
	TBool iCipherSuitesPresent;
	RArray<TUint> iCipherSuites;

	// In EAP-PEAP is version 0 allowed
	TBool iPEAPVersionsPresent;
	TBool iPEAPv0Allowed;
	TBool iPEAPv1Allowed;
	TBool iPEAPv2Allowed;
  	  
  	// Array listing the allowed certificates for EAP-TLS/TTLS/PEAP.
  	// Subject key ID and Certificate type are the only mandatory certificate 
  	// details needed at the moment.
  	TBool iCertificatesPresent;
	RPointerArray<EapCertificateEntry> iCertificates;

	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Use this in new code.
	// Array listing the enabled encapsulated Expanded EAP types (in priority order).
	// Use constant Expanded EAP type values from EapExpandedType.h.
	TBool iEnabledEncapsulatedEAPExpandedTypesPresent;
	RArray<TEapExpandedType> iEnabledEncapsulatedEAPExpandedTypes;
	
	// Use this in new code.
	// Array listing the disabled encapsulated Expanded EAP types.
	// Use constant Expanded EAP type values from EapExpandedType.h.
	TBool iDisabledEncapsulatedEAPExpandedTypesPresent;
	RArray<TEapExpandedType> iDisabledEncapsulatedEAPExpandedTypes;
	
	// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

	// Whether Authenticated provisioning mode allowed or not in EAP-FAST.
	TBool iAuthProvModeAllowedPresent;
	TBool iAuthProvModeAllowed;

	// Whether Unauthenticated provisioning mode allowed or not in EAP-FAST.
	TBool iUnauthProvModeAllowedPresent;
	TBool iUnauthProvModeAllowed;
	
	// PAC group reference in ASCII format for EAP-FAST.
	TBool iPACGroupReferencePresent;
	TBuf<KGeneralStringMaxLength> iPACGroupReference;
	
	// Whether to Warn (or Prompt) for ADHP (Authenticated Diffie-Hellman Protocol) 
	// auto-provisioning when there is no PAC at all. EAP-FAST specific.
	TBool iWarnADHPNoPACPresent;	
	TBool iWarnADHPNoPAC;

	// Whether to Warn (or Prompt) for ADHP auto-provisioning when 
	// there is no PAC that matches the A-ID sent by server. EAP-FAST specific.
	TBool iWarnADHPNoMatchingPACPresent;	
	TBool iWarnADHPNoMatchingPAC;
	
	// Whether to Warn (or Prompt) when client encouters a server that has provisioned 
	// the client with a PAC before but is not currently selected as the default server. 
	// EAP-FAST specific.
	TBool iWarnNotDefaultServerPresent;
	TBool iWarnNotDefaultServer;
	
	TBool iShowPassWordPromptPresent;
	TBool iShowPassWordPrompt;

	// This is used in TLS/PEAP/TTLS/FAST. It activates TLS-renegotiation, that will send user certificate with in TLS-protected application data.
	TBool iUseIdentityPrivacyPresent;
	TBool iUseIdentityPrivacy;

};

//#include "EapSettings.inl"

//-------------------------------------------------------------------------------

#if defined(USE_EAP_TRACE)

	#define EAP_TRACE_SETTINGS(settings) { (settings)->trace(); }

#else

	#define EAP_TRACE_SETTINGS(settings)

#endif //#if defined(USE_EAP_TRACE)


//-------------------------------------------------------------------------------

#endif

// End of file
