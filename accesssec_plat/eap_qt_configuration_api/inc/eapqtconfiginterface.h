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
 *   EAP method configuration QT interface
 *
 */

/*
 * %version: 9 %
 */

#ifndef EAPQTCONFIGINTERFACE_H
#define EAPQTCONFIGINTERFACE_H

// System includes
#include <qglobal.h>
#include <eapqtconfig.h>
#include <eapqtconfigexport.h>
#include <eapqtpacstoreconfig.h>

// User includes

// Forward declarations
class CpBaseSettingView;
class EapQtValidator;
class EapQtPluginInfo;
class EapQtPluginHandle;
class EapQtExpandedEapType;
class EapQtCertificateInfo;
class EapQtConfigInterfacePrivate;

// External data types

// Constants

// Class declaration
class EAP_QT_CONFIG_INTERFACE_EXPORT EapQtConfigInterface
{

public:

    // Data types

    // bearer type used for creating an interface object
    enum EapBearerType
    {
        // EAP configuration interface for WLAN
        EapBearerTypeWlan = 0,
        // EAP configuration interface for VPN
        EapBearerTypeVpn
    };

    // IAP ID to be used for accessing limited number of
    // API methods, see below the method descriptions
    static const int IapIdUndefined = -1;

    // NOTE: the default constuctor can only be used for creating validators
    // with validatorEap() and validatorPacStore(), and accessing EAP-FAST PAC store,
    // any other call throws an exception;
    // also, throws an exception if the construction fails
    EapQtConfigInterface();

    // this is the constructor for using the interface for all
    // available operations, including validators;
    // throws an exception if the construction fails;
    // the parameter iapId is the identifier of the configured IAP;
    // if iapId is negative (i.e. IapIdUndefined or negative), only a limited set of
    // methods are available and setConfigurationReference must be later called to
    // correct the IAP ID and use the rest of the API methods
    EapQtConfigInterface(const EapBearerType bearerType, const int iapId);

    // destructor
    ~EapQtConfigInterface();

    // method for creating a setting validator for the specified EAP method
    // NOTE: CALLER OWNS the returned object
    // returns NULL on failure (e.g. if the requested validator does not exist)
    EapQtValidator *validatorEap(const EapQtExpandedEapType &type, const EapQtConfig::SettingsId id) const;

    // method for creating a EAP-FAST PAC store validator, see also EapQtPacStoreConfig
    // NOTE: CALLER OWNS the returned object
    // returns NULL on failure (e.g. if EAP-FAST is not supported)
    EapQtValidator *validatorPacStore(const EapQtPacStoreConfig::PacStoreSettings id) const;

    // reads EAP-FAST PAC store configuration, see EapQtPacStoreConfig
    // returns false on failure (e.g. if EAP-FAST is not supported)
    bool readPacStoreConfiguration(EapQtPacStoreConfig &config) const;

    // stores EAP-FAST PAC store configuration, see EapQtPacStoreConfig
    // returns false on failure (e.g. if EAP-FAST is not supported)
    bool savePacStoreConfiguration(const EapQtPacStoreConfig &config) const;

    /**
     * NOTE: all the following methods throw an exception if the interface
     * instance was created with the default (validator) constructor;
     * otherwise the return value is as defined
     */

    // sets the IAP ID for accesssing EAP settings with the other methods
    // returns false on failure (e.g. WLAN IAP with the specified ID
    // [if the ID is other than IapIdUndefined] does not exist)
    bool setConfigurationReference(const int iapId) const;

    // returns supported outer EAP types
    // returns empty list on failure
    QList<EapQtPluginInfo> supportedOuterTypes() const;

    // returns supported inner EAP types for the specified outer type
    // returns empty list on failure
    QList<EapQtPluginInfo> supportedInnerTypes(const EapQtPluginHandle &outerType) const;

    // retrieves the list of installed CA certificates;
    // list returned from device database only when called for the first time,
    // otherwise returns the list from cache;
    // call updateCertificates() to update the cache;
    // returns empty list on failure or if CA certificates do not exist
    QList<EapQtCertificateInfo> certificateAuthorityCertificates() const;

    // retrieves the lsit of installed user certificate list;
    // list returned from device database only when called for the first time,
    // otherwise returns the list from cache;
    // call updateCertificates() to update the cache;
    // returns empty list on failure or if user certificates do not exist
    QList<EapQtCertificateInfo> userCertificates() const;

    // updates CA and user certificate lists from the device database
    bool updateCertificates() const;

    // checks if the specified outer EAP is supported
    // returns true if supported, false otherwise
    bool isSupportedOuterType(const EapQtPluginHandle &handle) const;

    // checks if the specified inner EAP is supported inside the specified outer EAP
    // returns true if supported, false otherwise
    bool isSupportedInnerType(const EapQtPluginHandle &outerHandle,
        const EapQtPluginHandle &innerHandle) const;

    /**
     * NOTE: all the following methods return failure if the current IAP
     * ID is IapIdUndefined (or negative);
     * setConfigurationReference must be called first to correct the IAP ID
     */

    // returns the list of activated outer EAP methods for the IAP
    // returns empty list on failure
    QList<EapQtPluginHandle> selectedOuterTypes() const;

    // sets the list of activated outer EAP methods for the IAP
    // returns empty list on failure
    bool setSelectedOuterTypes(const QList<EapQtPluginHandle> &outerHandles) const;

    // reads the configuration for pluginHandle inside outerHandle
    // if outerHandle is EapQtPluginHandle::PluginUndefined, the configuration is read for
    // pluginHandle as outer type;
    // returns false on failure (e.g. outerHandle/pluginHandle is not supported)
    bool readConfiguration(const EapQtPluginHandle &outerHandle,
        const EapQtPluginHandle &pluginHandle, EapQtConfig &config) const;

    // stores the configuration for pluginHandle
    // in config:
    // if OuterType is defined, the configuration for pluginHandle is set inside this OuterType
    // if OuterType is not defined, pluginHandle is for an outer type
    // if InnerType is defined, the defined inner types in config are activated for pluginHandle
    // if InnerType is not defined, the pluginHandle does not activate any inner type (or they do not exist)
    // returns false on failure (e.g. pluginHandle is not supported)
    bool saveConfiguration(const EapQtPluginHandle &pluginHandle, const EapQtConfig &config) const;

    // deletes all EAP configurations for the current IAP ID
    bool deleteConfiguration() const;

    // returns control panel UI instance for the specified EAP method (pluginHandle)
    // outerHandle specifies if the UI is for pluginHandle as outer (EapQtPluginHandle::PluginUndefined) or
    // inner (other than EapQtPluginHandle::PluginUndefined) EAP method;
    // NOTE: CALLER OWNS the returned object;
    // returns NULL on failure (e.g. if the combination of outerHandle/pluginHandle is not supported)
    // NOTE: the method throws an exception if current IAP ID is IapIdUndefined (or negative);
    CpBaseSettingView *uiInstance(const EapQtPluginHandle &outerHandle,
        const EapQtPluginHandle &pluginHandle) const;

private:

    Q_DISABLE_COPY(EapQtConfigInterface)

private: // data

    QScopedPointer<EapQtConfigInterfacePrivate> d_ptr;

};

#endif // EAPQTCONFIGINTERFACE_H

