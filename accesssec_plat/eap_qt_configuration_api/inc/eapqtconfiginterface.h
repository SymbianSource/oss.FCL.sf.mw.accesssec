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
 *   EAP method configuration QT interface
 *
 */

/*
 * %version: 1 %
 */

#ifndef EAPQTCONFIGINTERFACE_H
#define EAPQTCONFIGINTERFACE_H

#include <qglobal.h>
#include <eapqtconfig.h>

/*!
 * @addtogroup group_eap_config_api
 * @{
 */

#ifdef BUILD_EAP_QT_CONFIG_INTERFACE_DLL
#define EAP_QT_CONFIG_INTERFACE_EXPORT Q_DECL_EXPORT
#else
#define EAP_QT_CONFIG_INTERFACE_EXPORT Q_DECL_IMPORT
#endif

class CpBaseSettingView;
class EapQtValidator;
class EapQtPluginInfo;
class EapQtPluginHandle;
class EapQtExpandedEapType;
class EapQtCertificateInfo;
class EapQtConfigInterfacePrivate;
/*!
 */
class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtConfigInterface
{
public:

    enum EapBearerType
    {
        // EAP configuration interface for WLAN
        EapBearerTypeWlan,
        // EAP configuration interface for VPN
        EapBearerTypeVpn,
    };

    static const int IAP_ID_UNDEFINED = -1;

public:

    // the default constuctor can only be used for validators,
    // any other call throws an exeption;
    // throws an exception if the contruction fails
    EapQtConfigInterface();

    EapQtValidator *validatorEap(EapQtExpandedEapType type, EapQtConfig::SettingsId id);

    // this is the constructor for using the interface for all
    // available operations, including validators;
    // throws an exeption if the contruction fails;
    // the parameter iapId is the IAP ID;
    // if iapId is negative, only a limited set of methods are availble and
    // setConfigurationReference must be later called to set the correct IAP ID
    EapQtConfigInterface(const EapBearerType bearerType, const int iapId);

    ~EapQtConfigInterface();

    // if iapId was IAP_ID_UNDEFINED (or negative) in the constructor, this method
    // must be called before calling the following methods
    bool setConfigurationReference(const int iapId) const;

    /**
     * all the following methods throw an exception if the instance
     * was created with the default constructor;
     * otherwise the return value is as defined
     */

    // returns empty list on failure
    QList<EapQtPluginInfo> supportedOuterTypes() const;
    // returns empty list on failure
    QList<EapQtPluginInfo> supportedInnerTypes(const EapQtPluginHandle outerType) const;

    // returns empty list on failure
    QList<EapQtCertificateInfo> certificateAuthorityCertificates() const;
    // returns empty list on failure
    QList<EapQtCertificateInfo> userCertificates() const;

    // returns null on failure
    CpBaseSettingView *uiInstance(const EapQtPluginHandle& outerHandle,
        const EapQtPluginHandle& pluginHandle) const;

    // returns empty list on failure
    QList<EapQtPluginHandle> selectedOuterTypes() const;

    // returns true if supported, false otherwise
    bool isSupportedOuterType(const EapQtPluginHandle& handle) const;
    bool isSupportedInnerType(const EapQtPluginHandle& outerHandle,
        const EapQtPluginHandle& innerHandle) const;

    /**
     * all the following methods throw an exception if the instance
     * was created with the default constructor;
     * otherwise the methods return true on success and false on failure
     */

    bool setSelectedOuterTypes(const QList<EapQtPluginHandle>& outerHandles) const;

    bool readConfiguration(const EapQtPluginHandle& outerHandle,
        const EapQtPluginHandle& pluginHandle, EapQtConfig &config) const;
    bool saveConfiguration(const EapQtPluginHandle& pluginHandle, EapQtConfig &config) const;
    bool deleteConfiguration() const;

private:
    Q_DISABLE_COPY(EapQtConfigInterface)
    QScopedPointer<EapQtConfigInterfacePrivate> d_ptr;
};

/*! @} */

#endif

