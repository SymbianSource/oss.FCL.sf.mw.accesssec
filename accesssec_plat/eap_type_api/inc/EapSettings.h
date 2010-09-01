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
* %version: 11.1.2.1.3 %
*/

// Refer the document S60_3_1_EAP_Symbian_Adaptation_Design_C.doc for more 
// details of using EAPSettings. Refer section 9.2 for code samples.

#ifndef EAP_SETTINGS_H
#define EAP_SETTINGS_H

const TUint KGeneralStringMaxLength = 255;
const TUint KKeyIdentifierLength = 255;
const TUint KThumbprintMaxLength = 64;

class CertificateEntry
{
public:

	CertificateEntry();

	enum TCertType {
		EUser,
		ECA
	};

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
	
	// Subject key in binary form. This is mandatory.
	TBool iSubjectKeyIDPresent;
	TBuf8<KKeyIdentifierLength> iSubjectKeyID;
	
	// Thumbprint in binary form. This is optional.
	TBool iThumbprintPresent;
	TBuf<KThumbprintMaxLength> iThumbprint;
};

class EAPSettings : public CBase
{
public:	

	EAPSettings();
		
	enum TEapType
	{
		EEapNone		= 0,
		EEapGtc			= 6,
		EEapTls			= 13,
		EEapLeap		= 17,
		EEapSim			= 18,
		EEapTtls		= 21,
		EEapAka			= 23,
		EEapPeap		= 25,
		EEapMschapv2	= 26,
		EEapSecurid		= 32,
		EEapFast		= 43,
		ETtlsPlainPap   = 98,
		EPlainMschapv2	= 99		
	};

	// Specifies the EAP type these settings are for. 
	// Is not really needed but is here so just some sanity checks can be made
	TEapType iEAPType; 
	
	// Username in ASCII format
	TBool iUsernamePresent;
	TBuf<KGeneralStringMaxLength> iUsername; 
		
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
	CArrayFixFlat<CertificateEntry> iCertificates;
	
	// Array listing the encapsulated EAP types (in priority order).
	// Use EAP type values from TEapType.
	TBool iEncapsulatedEAPTypesPresent;
	RArray<TUint> iEncapsulatedEAPTypes;
	
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
};

#include "EapSettings.inl"

#endif
// End of file
