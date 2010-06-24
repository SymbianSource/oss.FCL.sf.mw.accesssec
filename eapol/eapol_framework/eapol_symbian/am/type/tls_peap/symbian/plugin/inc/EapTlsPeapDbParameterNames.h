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
* %version: 20.1.4 %
*/

#if !defined(_EAPTLAPEAPDBPARAMETERNAMES_H_)
#define _EAPTLAPEAPDBPARAMETERNAMES_H_

#include "eap_type_tls_peap_types.h"

// LOCAL CONSTANTS

_LIT(KServiceType, "ServiceType");
_LIT(KServiceIndex, "ServiceIndex");
_LIT(KTunnelingTypeVendorId, "TunnelingTypeVendorId");
_LIT(KTunnelingType, "TunnelingType");
_LIT(KCACertLabel, "CA_cert_label");
_LIT(KClientCertLabel, "client_cert_label");
_LIT(KCertLabel, "label");
_LIT(KCipherSuite, "cipher_suite");
_LIT(KSerialNumber, "SerialNumber");
_LIT(KIssuerName, "IssuerName");
_LIT(KSubjectName, "SubjectName");
_LIT(KSubjectKeyIdentifier, "SubjectKeyId"); // This stores the Symbian's subjectkey id (hash of actual subjectkey id).
											 // This is the subjectkey id used in authentications.

_LIT(KTLSLastFullAuthTime, "EAP_TLS_last_full_authentication_time");
_LIT(KPEAPLastFullAuthTime, "EAP_PEAP_last_full_authentication_time");
_LIT(KTTLSLastFullAuthTime, "EAP_TTLS_last_full_authentication_time");
_LIT(KFASTLastFullAuthTime, "EAP_FAST_last_full_authentication_time");
_LIT(KFASTLastPasswordIdentityTime, "EAP_FAST_last_password_identity_time");
_LIT( KTTLSPAPLastFullAuthTime, "EAP_TTLS_PAP_last_full_authentication_time" );

// This is the subject key id present in the certificate itself, which OMA provisioning (Device Management)
// sets through EAPSettings. KSubjectKeyIdentifier -> stores the Symbian's subjectkey id (hash of actual subjectkey id).
// This is used only to provide GetConfigurationL the value set by SetConfigurationL
// No other use of this value, at the moment.
_LIT(KActualSubjectKeyIdentifier, "ActualSubjectKeyId");
_LIT(KThumbprint, "Thumbprint");

#ifdef USE_FAST_EAP_TYPE
_LIT(KFASTPACGroupDBReferenceCollection, "EAP_FAST_PAC_Group_DB_Reference_Collection");
_LIT(KFASTPACGroupImportReferenceCollection, "EAP_FAST_PAC_Group_Import_Reference_Collection");
_LIT(KFASTWarnADHPNoPAC, "EAP_FAST_Warn_ADHP_No_PAC");
_LIT(KFASTWarnADHPNoMatchingPAC, "EAP_FAST_Warn_ADHP_No_Matching_PAC");
_LIT(KFASTWarnNotDefaultServer, "EAP_FAST_Warn_Not_Default_Server");

// For PAC store.
_LIT(KPACStoreReferenceCounter, "EAP_PAC_Store_Referance_Counter");
_LIT(KPACStoreMasterKey, "EAP_PAC_Store_Master_Key");
_LIT(KPACStoreGroupReference, "EAP_PAC_Store_Group_Reference");
_LIT(KPACStoreGroupValue, "EAP_FAST_Group_Value");
_LIT(KPACStoreAIDReference, "EAP_PAC_Store_AID_Reference");
_LIT(KPACStoreAIDValue, "EAP_PAC_Store_AID_Value");
_LIT(KPACStorePACReference, "EAP_PAC_Store_PAC_Reference");
_LIT(KPACStorePACValue, "EAP_PAC_Store_PAC_Value");

#endif //#ifdef USE_FAST_EAP_TYPE

#ifndef USE_EAP_TLS_IDENTITY_PRIVACY
_LIT(cf_str_EAP_TLS_PEAP_use_identity_privacy_literal, "EAP_TLS_PEAP_use_identity_privacy");
#endif

#endif // _EAPTLAPEAPDBPARAMETERNAMES_H_


// End of file
