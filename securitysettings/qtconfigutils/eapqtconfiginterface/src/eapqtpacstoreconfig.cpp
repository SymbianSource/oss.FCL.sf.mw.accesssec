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
 *   EAP-FAST PAC store configuration data
 *
 */

/*
 * %version: 2 %
 */

// System includes
#include <eapqtpacstoreconfig.h>

// User includes
#include "eapqtpacstoreconfig_p.h"

/*!
 *  \class EapQtPacStoreConfig
 *  \brief Public implementation of EAP-FAST PAC store configuration data
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtPacStoreConfig::EapQtPacStoreConfig() :
    d_ptr(new EapQtPacStoreConfigPrivate)
{
}

EapQtPacStoreConfig::~EapQtPacStoreConfig()
{
    // scoped pointer deleted automatically
}

QVariant EapQtPacStoreConfig::value(const PacStoreSettings id) const
{
    // check for valid range, otherwise memory is consumed for no reason
    if(id >= PacStoreLast) {
        qDebug("ERROR: EapQtPacStoreConfig::value - invalid id!");
        return QVariant::Invalid;
    }
    return d_ptr->mPacStoreSettings[id];
}

void EapQtPacStoreConfig::setValue(const PacStoreSettings id, const QVariant &newValue) const
{
    // check for valid range, otherwise memory is consumed for no reason
    if (id < PacStoreLast) {
        d_ptr->mPacStoreSettings[id] = newValue;
    }
    else {
        qDebug("ERROR: EapQtPacStoreConfig::setValue - invalid id!");
    }
}

void EapQtPacStoreConfig::clear() const
{
    d_ptr->mPacStoreSettings.clear();
}
