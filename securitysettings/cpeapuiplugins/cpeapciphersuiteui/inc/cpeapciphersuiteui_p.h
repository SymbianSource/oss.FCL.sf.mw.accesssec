/*
* Copyright (c) 2010 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of "Eclipse Public License v1.0"
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
* %version: 4 %
*/

#ifndef CP_EAP_CIPHERSUITE_UI_P_H
#define CP_EAP_CIPHERSUITE_UI_P_H

// System includes
#include <hbdataformmodelitem.h> 

// User includes

// Forward declarations
class CpSettingFormItemData;

// External data types

// Constants

/*!
 * @addtogroup group_eap_cipher_suite
 * @{
 */

class CpEapCiphersuiteUiPrivate
{
public:
    CpEapCiphersuiteUiPrivate();
    
    ~CpEapCiphersuiteUiPrivate();

    int ciphersuiteSelected(QVariant suites, int id);

    CpSettingFormItemData* createGroupItem(
        QVariant &suites, QString name, int id);
    
private:
    friend class CpEapCiphersuiteUi;
    QHash<HbDataFormModelItem*, int> mSuiteMapper;
};

/*! @} */

#endif
