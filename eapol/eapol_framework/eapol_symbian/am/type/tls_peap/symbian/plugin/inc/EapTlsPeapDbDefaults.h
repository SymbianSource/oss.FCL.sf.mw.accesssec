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
* %version: 36.1.8 %
*/

#if !defined(_EAPTLSPEAPDBDEFAULTS_H_)
#define _EAPTLSPEAPDBDEFAULTS_H_

#include "EapPluginDbDefaults.h"
#include "tls_peap_types.h"

// LOCAL CONSTANTS
const TInt default_EAP_TLS_PEAP_use_manual_realm = EEapDbFalse;

const TInt default_EAP_TLS_PEAP_use_manual_username = EEapDbFalse;

const TInt default_EAP_TLS_PEAP_cipher_suite = tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA;

const TInt default_EAP_TLS_PEAP_used_PEAP_version = 0;
const TInt default_EAP_TLS_PEAP_accepted_PEAP_versions[] = {0, 1, -1};

_LIT8(default_PEAP_tunneled_types, "");

const TInt default_EAP_TLS_server_authenticates_client = 1;
const TInt default_EAP_PEAP_TTLS_server_authenticates_client = 0;

_LIT(default_CA_cert_label, "");
_LIT(default_client_cert_label, "");

const TInt default_EAP_TLS_PEAP_verify_certificate_realm = 0;

const TUint default_EAP_TLS_PEAP_TTLS_Privacy = EEapDbFalse;

const TUint default_EAP_TLS_PEAP_use_automatic_ca_certificate = EEapDbTrue;

// Defaults for EAP-FAST specific items
#ifdef USE_FAST_EAP_TYPE
const TUint default_EAP_FAST_Auth_Prov_Mode_Allowed = EEapDbFalse; // Default is NO
const TUint default_EAP_FAST_Unauth_Prov_Mode_Allowed = EEapDbFalse; // Default is NO
const TUint default_EAP_FAST_Warn_ADHP_No_PAC = EEapDbTrue; // Default is YES
const TUint default_EAP_FAST_Warn_ADHP_No_Matching_PAC = EEapDbTrue; // Default is YES
const TUint default_EAP_FAST_Warn_Not_Default_Server = EEapDbTrue; // Default is YES
#endif //#ifdef USE_FAST_EAP_TYPE

// Add here the cipher suites you want to be allowed by default. Note that the last
// element must be 0.
const TInt default_allowed_cipher_suites[] = {
	tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA, 
	tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA,
	tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	0
};

const TInt available_cipher_suites[] = {
	tls_cipher_suites_TLS_RSA_WITH_3DES_EDE_CBC_SHA, 
	tls_cipher_suites_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA,
	tls_cipher_suites_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA,
	tls_cipher_suites_TLS_RSA_WITH_AES_128_CBC_SHA,
	tls_cipher_suites_TLS_DHE_DSS_WITH_AES_128_CBC_SHA,
	tls_cipher_suites_TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
	tls_cipher_suites_TLS_RSA_WITH_RC4_128_MD5,
    tls_cipher_suites_TLS_RSA_WITH_RC4_128_SHA,
	0
};

const TUint KMaxCertLabelLengthInDB = 255;
const TUint KMaxSubjectKeyIdLengthInDB = 255; // Not using KKeyIdentifierLength (EapSettings.h) as this is
											 // Symbian's subjectkey id (hash of actual subjectkey id), though the lengths are same.
const TUint KMaxSessionIdLengthInDB = 32;
const TUint KMaxMasterSecretLengthInDB = 48;
const TUint KMaxPEAPVersionsStringLengthInDB = 12;
const TUint KMaxTunneledTypeStringLengthInDB = 240; // 8 bytes for an EAP type. So 30 EAP types can be stored with this size.


/**
* Possible values of password prompt.
*/ 
enum TPapPasswordPrompt
    {
    /**
    * False. Don't show password prompt.
    */ 
	EPapPasswordPromptOff,
	
	/**
	* True. Show password prompt.
	*/
	EPapPasswordPromptOn
    };

/**
* Default password prompt value.
*/ 
const TUint KDefaultPapPasswordPrompt = EPapPasswordPromptOn;

/**
* Maximum length of PAP user name according to UI spec.
*/ 
const TUint KMaxPapUserNameLengthInDb = 253;

/**
* Maximum length of PAP password according to UI spec.
*/ 
const TUint KMaxPapPasswordLengthInDb = 128;

/**
* Default PAP user name.
*/ 
_LIT( KDefaultPapUserName, "" );

/**
* Default PAP password.
*/
_LIT( KDefaultPapPassword, "" );

/**
* Default max PAP session time.
* Value 0 means reading from configuration file.
*/ 
const TInt64 KDefaultMaxPapSessionTime = 0; 

/**
* Default full PAP authentication time.
*/ 
const TInt64 KDefaultFullPapAuthTime = 0;

#endif // _EAPTLSPEAPDBDEFAULTS_H_

// End of file
