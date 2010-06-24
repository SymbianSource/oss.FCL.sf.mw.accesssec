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
 *   Certificate information data structure for EAP QT configuration interface
 *
 */

/*
 * %version: 6 %
 */

// System includes

// User includes
#include "eapqtcertificateinfo_p.h"

/*!
 *  \class EapQtCertificateInfoPrivate
 *  \brief Private implementation of certificate information data
 *         structure for EAP QT configuration interface
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtCertificateInfoPrivate::EapQtCertificateInfoPrivate()
{
}

EapQtCertificateInfoPrivate::~EapQtCertificateInfoPrivate()
{
}

EapQtCertificateInfoPrivate::EapQtCertificateInfoPrivate(
    const EapQtCertificateInfoPrivate &certInfo)
{
    mCerts = certInfo.mCerts;
}

QVariant EapQtCertificateInfoPrivate::value(const int id)
{
    return mCerts[id];
}

void EapQtCertificateInfoPrivate::setValue(const int id, const QVariant &newValue)
{
    mCerts[id] = newValue;
}

void EapQtCertificateInfoPrivate::clear()
{
    mCerts.clear();
}
