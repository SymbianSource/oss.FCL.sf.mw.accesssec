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


inline CertificateEntry::CertificateEntry()
: iCertType(ECA)
, iSubjectNamePresent(EFalse)
, iIssuerNamePresent(EFalse)
, iSerialNumberPresent(EFalse)
, iSubjectKeyIDPresent(EFalse)
, iThumbprintPresent(EFalse)
{
}

inline EAPSettings::EAPSettings()
: iUsernamePresent(EFalse)
, iPasswordPresent(EFalse)
, iRealmPresent(EFalse)
, iVerifyServerRealmPresent(EFalse)
, iRequireClientAuthenticationPresent(EFalse)
, iSessionValidityTimePresent(EFalse)
, iCipherSuitesPresent(EFalse)
, iCipherSuites(1)
, iPEAPVersionsPresent(EFalse)
, iCertificatesPresent(EFalse)
, iCertificates(1)
, iEncapsulatedEAPTypesPresent(EFalse)
, iEncapsulatedEAPTypes(1)
{
}

// end of file
