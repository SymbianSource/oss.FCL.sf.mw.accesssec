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
 *   Certificate information data structure for EAP QT
 *   configuration interface
 *
 */

/*
 * %version: 5 %
 */

#ifndef EAPQTCERTIFICATEINFO_H
#define EAPQTCERTIFICATEINFO_H

// System includes
#include <QMetaType>
#include <QVariant>
#include <eapqtconfigexport.h>

// User includes

// Forward declarations
class EapQtCertificateInfoPrivate;

// External data types

// Constants

// Class declaration
class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtCertificateInfo
{

public:

    // Data types

    enum ItemId
    {
        /*! QString */
        SubjectName = 0,
        /*! QString */
        IssuerName,
        /*! QString */
        SerialNumber,
        /*! QByteArray */
        SubjectKeyId,
        /*! QString */
        ThumbPrint,
        /*! QString */
        CertificateLabel,
        /* marker for the last item */
        ItemIdLast
    };

    // default constructor
    EapQtCertificateInfo();
    // destructor
    ~EapQtCertificateInfo();

    // copy constuctor
    EapQtCertificateInfo(const EapQtCertificateInfo& certInfo);
    // assignment
    EapQtCertificateInfo &operator=(const EapQtCertificateInfo& certInfo);

    // gets the certificate field referred to by an id from ItemId
    // returns QVariant::Invalid is the field has not been set
    QVariant value(const ItemId id) const;

    // sets the certificate field referred to by an id from ItemId
    // does nothing if newValue >= ItemIdLast
    void setValue(const ItemId id, const QVariant& newValue) const;

    // resets the object i.e. any successive call to
    // value() returns QVariant::Invalid
    void clear() const;

private: // data

    QScopedPointer<EapQtCertificateInfoPrivate> d_ptr;

};

// Make the class known to QMetaType to support using QVariant
Q_DECLARE_METATYPE(EapQtCertificateInfo)

#endif // EAPQTCERTIFICATEINFO_H
