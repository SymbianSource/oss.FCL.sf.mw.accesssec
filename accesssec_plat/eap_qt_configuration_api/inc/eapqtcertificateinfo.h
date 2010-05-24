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
 *   Certificate information data structure for EAP QT
 *   configuration interface
 *
 */

/*
 * %version: 1 %
 */

#ifndef EAPQTCERTIFICATEINFO_H
#define EAPQTCERTIFICATEINFO_H

#include <QMetaType>
#include <QVariant>

#ifdef BUILD_EAP_QT_CONFIG_INTERFACE_DLL
#define EAP_QT_CERTIFICATE_INFO_EXPORT Q_DECL_EXPORT
#else
#define EAP_QT_CERTIFICATE_INFO_EXPORT Q_DECL_IMPORT
#endif

class EapQtCertificateInfoPrivate;

class EAP_QT_CERTIFICATE_INFO_EXPORT EapQtCertificateInfo
{
public:

    enum ItemId
    {
        /*! QString */
        SubjectName,
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
        /*! marker for the last item */
        ItemIdLast
    };

public:

    EapQtCertificateInfo();
    ~EapQtCertificateInfo();

    EapQtCertificateInfo(const EapQtCertificateInfo &certInfo);
    EapQtCertificateInfo &operator=(const EapQtCertificateInfo &certInfo);

    QVariant value(ItemId id) const;
    void setValue(ItemId id, QVariant newValue);

private:

    QScopedPointer<EapQtCertificateInfoPrivate> d_ptr;
};

// Make the class known to QMetaType to support using QVariant
Q_DECLARE_METATYPE(EapQtCertificateInfo)

#endif /* EAPQTCERTIFICATEINFO_H */
