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
* %version: 22.1.2 %
*/

#ifndef _EAPTLSPEAPUTILS_H_
#define _EAPTLSPEAPUTILS_H_

// INCLUDES
#include <d32dbms.h>
#include <EapType.h>
#include "eap_am_tools_symbian.h"
#include <CertEntry.h>

#include <unifiedcertstore.h>
#include <mctwritablecertstore.h>

#ifndef USE_EAP_EXPANDED_TYPES
// This dependencay is needed only for non-expanded EAP types.
#include <wdbifwlansettings.h>
#endif //#ifndef USE_EAP_EXPANDED_TYPES

#include "eap_type_tls_peap_types.h"
#include "eap_header.h"

// LOCAL CONSTANTS

#ifdef USE_EAP_EXPANDED_TYPES

// Size of Expanded EAP Type
const TUint8 KExpandedEAPTypeSize = 8;

struct SExpandedEAPType
{
	// Unique ID for an expanded EAp type.
	// This includes, Type (1 byte), Vendor-Id (3bytes) and Vendor-Type (4bytes).
	TBuf8<KExpandedEAPTypeSize>    iExpandedEAPType;
};

typedef RPointerArray<SExpandedEAPType> RExpandedEapTypePtrArray;

#endif //#ifdef USE_EAP_EXPANDED_TYPES

#ifdef SYMBIAN_SECURE_DBMS
// For EAP TLS, PEAP, TTLS, FAST secure databases.
// Full path is not needed. The database eaptls.dat will be saved in the 
// data cage path for DBMS. So it will be in "\private\100012a5\eaptls.dat" in C: drive.
// The maximum length of database name is 0x40 (KDbMaxName) , which is defined in d32dbms.h.

_LIT(KTlsDatabaseName, "c:eaptls.dat");
_LIT(KPeapDatabaseName, "c:eappeap.dat");
_LIT(KTtlsDatabaseName, "c:eapttls.dat");
_LIT(KFastDatabaseName, "c:eapfast.dat");

_LIT(KSecureUIDFormat, "SECURE[102072e9]"); // For the security policy.

#else

_LIT(KTlsDatabaseName, "c:\\system\\data\\eaptls.dat");
_LIT(KPeapDatabaseName, "c:\\system\\data\\eappeap.dat");
_LIT(KTtlsDatabaseName, "c:\\system\\data\\eapttls.dat");
_LIT(KFastDatabaseName, "c:\\system\\data\\eapfast.dat");

#endif // #ifdef SYMBIAN_SECURE_DBMS

// For TLS.
_LIT(KTlsDatabaseTableName, "eaptls");
_LIT(KTlsAllowedUserCertsDatabaseTableName, "eaptls_usercerts");
_LIT(KTlsAllowedCACertsDatabaseTableName, "eaptls_cacerts");
_LIT(KTlsAllowedCipherSuitesDatabaseTableName, "eaptls_ciphersuites");

// For PEAP.
_LIT(KPeapDatabaseTableName, "eappeap");
_LIT(KPeapAllowedUserCertsDatabaseTableName, "eappeap_usercerts");
_LIT(KPeapAllowedCACertsDatabaseTableName, "eappeap_cacerts");
_LIT(KPeapAllowedCipherSuitesDatabaseTableName, "eappeap_ciphersuites");

// For TTLS.
_LIT(KTtlsDatabaseTableName, "eapttls");
_LIT(KTtlsAllowedUserCertsDatabaseTableName, "eapttls_usercerts");
_LIT(KTtlsAllowedCACertsDatabaseTableName, "eapttls_cacerts");
_LIT(KTtlsAllowedCipherSuitesDatabaseTableName, "eapttls_ciphersuites");

// For FAST.
_LIT(KFastGeneralSettingsDBTableName, "eapfast_general_settings"); // Generic settings (similar to TTLS etc) for EAP-FAST.
_LIT(KFastSpecialSettingsDBTableName, "eapfast_special_settings"); // Only for EAP-FAST specific (PAC etc) settings.
_LIT(KFastAllowedUserCertsDatabaseTableName, "eapfast_usercerts");
_LIT(KFastAllowedCACertsDatabaseTableName, "eapfast_cacerts");
_LIT(KFastAllowedCipherSuitesDatabaseTableName, "eapfast_ciphersuites");

enum TAlterTableCmd
{
EAddColumn,
ERemoveColumn
};

// CLASS DECLARATION
class EapTlsPeapUtils 
{
public:	
	static void OpenDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		eap_type_value_e aEapType);

	/**
	* Changes the settings' index
	*/	
	static void SetIndexL(
		RDbNamedDatabase& aDatabase,
		const TDesC& aTableName,	
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const TIndexType aNewIndexType,
		const TInt aNewIndex,
		const eap_type_value_e aNewTunnelingType);
		
	static void SetConfigurationL(
		RDbNamedDatabase& aDatabase,
		const EAPSettings& aSettings, 
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType);

	static void GetConfigurationL(
		RDbNamedDatabase& aDatabase,
		EAPSettings& aSettings, 
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType);

	static void CopySettingsL(
		RDbNamedDatabase& aDatabase,
		const TDesC& aTableName,
		const TIndexType aSrcIndexType,
		const TInt aSrcIndex,
		const eap_type_value_e aSrcTunnelingType,
		const TIndexType aDestIndexType,
		const TInt aDestIndex,
		const eap_type_value_e aDestTunnelingType);

	static void DeleteConfigurationL(		
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType);

	static void ReadCertRowsToArrayL(
		RDbNamedDatabase& aDatabase,
		eap_am_tools_symbian_c * const aTools,
		const TDesC& aTableName, 
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		RArray<SCertEntry>& aArray);

	static void ReadUintRowsToArrayL(
		RDbNamedDatabase& aDatabase,
		eap_am_tools_symbian_c * const aTools,
		const TDesC& aTableName, 
		const TDesC& aColumnName,	
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		RArray<TUint>& aArray);

#ifdef USE_EAP_EXPANDED_TYPES
	
	// Stores the tunneled EAP type (expanded) to the database.
	static void SetTunnelingExpandedEapDataL(
		RDbNamedDatabase& aDatabase,
		eap_am_tools_symbian_c * const aTools,
		RExpandedEapTypePtrArray &aEnabledEAPArrary,
		RExpandedEapTypePtrArray &aDisabledEAPArrary,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType);

	// Retrieves the tunneled EAP type (expanded) from the database	.
	static void GetTunnelingExpandedEapDataL(
		RDbNamedDatabase& aDatabase,
		eap_am_tools_symbian_c * const aTools,
		RExpandedEapTypePtrArray &aEnabledEAPArrary,
		RExpandedEapTypePtrArray &aDisabledEAPArrary,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType);

#else // For normal EAP types.

	// This sets only the tunneling EAP types.
	static void SetEapDataL(
		RDbNamedDatabase& aDatabase,
		eap_am_tools_symbian_c * const aTools,
		TEapArray &aEaps,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType);
	
	// This gets only the tunneling EAP types.	
	static void GetEapDataL(
		RDbNamedDatabase& aDatabase,
		eap_am_tools_symbian_c * const aTools,
		TEapArray &aEaps,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType);

#endif //#ifdef USE_EAP_EXPANDED_TYPES

	static TBool CompareTCertLabels(
		const TCertLabel& item1, 
		const TCertLabel& item2);

	static TBool CompareSCertEntries(const SCertEntry& item1, const SCertEntry& item2);

	static TBool CipherSuiteUseRSAKeys(tls_cipher_suites_e aCipherSuite);

	static TBool CipherSuiteUseDSAKeys(tls_cipher_suites_e aCipherSuite);
	
	static TBool CipherSuiteIsEphemeralDHKeyExchange(tls_cipher_suites_e aCipherSuite);
	
	static void GetEapSettingsDataL(
		RDbNamedDatabase& aDatabase,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType,
		const TDesC& aDbColumnName,
		eap_variable_data_c * const aDbColumnValue);			

	static void SetEapSettingsDataL(
		RDbNamedDatabase& aDatabase,
		const TIndexType aIndexType,
		const TInt aIndex,
		const eap_type_value_e aTunnelingType,
		const eap_type_value_e aEapType,
		const TDesC& aDbColumnName,
		const eap_variable_data_c * const aDbColumnValue);		

private:
	static void OpenTlsDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);

	static void OpenPeapDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);

#if defined(USE_TTLS_EAP_TYPE)
	static void OpenTtlsDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);
#endif // #if defined(USE_TTLS_EAP_TYPE)

#if defined(USE_FAST_EAP_TYPE)

	static void OpenFastDatabaseL(
		RDbNamedDatabase& aDatabase, 
		RDbs& aSession, 
		const TIndexType aIndexType, 
		const TInt aIndex,
		const eap_type_value_e aTunnelingType);

#endif // #if defined(USE_FAST_EAP_TYPE)

	static void AddExtraCertColumnsL(
		RDbNamedDatabase& aDatabase, 
		TDesC& aTableName);	

private:

	static void AlterTableL(
			RDbNamedDatabase& aDb,
			TAlterTableCmd aCmd,
			const TDesC& aTableName,
			const TDesC& aColumnName,
			const TDesC& aColumnDef );

};

#endif // _EAPTLSPEAPUTILS_H_

// End of file
