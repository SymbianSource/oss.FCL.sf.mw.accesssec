/*
* Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
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
* Description: 
*   Control Panel QT UI for TLS ciphersuite configiration in EAP methods
*
*/

/*
* %version: 2 %
*/


#ifndef CP_EAP_CIPHERSUITE_UI_H
#define CP_EAP_CIPHERSUITE_UI_H

/*!
 * @addtogroup group_eap_cipher_suite
 * @{
 */

#include <QVariant>
#include "cpsettingformitemdata.h"


#ifdef BUILD_CP_EAP_CIPHERSUITE_UI_DLL
#define CP_EAP_CIPHERSUITE_UI_EXPORT Q_DECL_EXPORT
#else
#define CP_EAP_CIPHERSUITE_UI_EXPORT Q_DECL_IMPORT
#endif

class CpEapCiphersuiteUiPrivate;

/*!
 */
class CP_EAP_CIPHERSUITE_UI_EXPORT CpEapCiphersuiteUi: public CpSettingFormItemData
{
public:
    CpEapCiphersuiteUi(CpItemDataHelper &dataHelpper, QVariant &ciphersuites);
    ~CpEapCiphersuiteUi();

    QVariant ciphersuites();

private:
    Q_DISABLE_COPY(CpEapCiphersuiteUi)
    CpEapCiphersuiteUi();
    CpEapCiphersuiteUiPrivate* d_ptr;
};


/*! @} */

#endif

