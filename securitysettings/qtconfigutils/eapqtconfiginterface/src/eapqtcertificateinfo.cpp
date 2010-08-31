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
#include <eapqtcertificateinfo.h>

// User includes
#include "eapqtcertificateinfo_p.h"

/*!
 *  \class EapQtCertificateInfo
 *  \brief Public implementation of certificate information data
 *         structure for EAP QT configuration interface
 */

// External function prototypes

// Local constants

// ======== LOCAL FUNCTIONS ========

// ======== MEMBER FUNCTIONS ========

EapQtCertificateInfo::EapQtCertificateInfo() :
    d_ptr(new EapQtCertificateInfoPrivate)
{
}

EapQtCertificateInfo::~EapQtCertificateInfo()
{
    // scoped pointer deleted automatically
}

EapQtCertificateInfo::EapQtCertificateInfo(const EapQtCertificateInfo &certInfo) :
    d_ptr(new EapQtCertificateInfoPrivate(*(certInfo.d_ptr)))
{
}

EapQtCertificateInfo& EapQtCertificateInfo::operator=(const EapQtCertificateInfo &certInfo)
{
    // check if assigning to myself
    if (this != &certInfo) {
        d_ptr.reset(new EapQtCertificateInfoPrivate(*(certInfo.d_ptr)));
    }
    return *this;
}

QVariant EapQtCertificateInfo::value(const ItemId id) const
{
    // check for valid range, otherwise memory is consumed for no reason
    if(id >= ItemIdLast) {
        qDebug("ERROR: EapQtCertificateInfo::value - invalid id!");
        return QVariant::Invalid;
    }
    return d_ptr->value(id);
}

void EapQtCertificateInfo::setValue(const ItemId id, const QVariant &newValue) const
{
    // check for valid range, otherwise memory is consumed for no reason
    if (id < ItemIdLast) {
        d_ptr->setValue(id, newValue);
    }
    else {
        qDebug("ERROR: EapQtCertificateInfo::setValue - invalid id!");
    }
}

void EapQtCertificateInfo::clear() const
{
    d_ptr->clear();
}
